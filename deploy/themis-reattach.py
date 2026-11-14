#!/usr/bin/env python3
"""Keep THEMIS reachable inside the live modelmarket-hub network namespace.

THEMIS has no network namespace of its own: it runs with ``--network container:<hub>``
because the hub calls the auditor at http://127.0.0.1:8080 and its SSRF guard exempts only
loopback. Two ways strand it, and its own healthcheck sees neither (it runs inside the
stranded namespace):

- the hub is RECREATED (new container ID): THEMIS still points at the old, deleted one
  (2026-09-08, my-vps);
- the hub is RESTARTED IN PLACE (same ID, new namespace): THEMIS's mode string still matches
  the hub, yet it sits in the dead namespace. 2026-11-14 on factory-vps: hub stop/start at
  05:30Z, themis.modelmarket.dev 502 until 09:07Z. The 09-08 script compared IDs only and
  would have reported "already attached".

So the test here is reachability, not configuration: from inside the hub container,
GET http://127.0.0.1:8080/health must answer 200. When it does not:

- same hub ID  -> ``docker restart themis`` (it re-joins the hub's current namespace and
  keeps every setting);
- other hub ID -> recreate THEMIS from its OWN inspected config (image, env, volumes,
  restart policy, labels, healthcheck), only the network pointed at the live hub. The old
  container is renamed and stopped first and removed only after the new one answers; if the
  new one does not, it is removed and the old one is put back. Volumes are never removed.

No dependencies beyond the Python standard library; talks to /var/run/docker.sock.
Exit status: 0 healthy (or nothing to do), 1 still unreachable after the repair.
"""

from __future__ import annotations

import copy
import fcntl
import http.client
import json
import os
import socket
import subprocess
import sys
import time

HUB = os.environ.get("HUB", "modelmarket-hub")
THEMIS = os.environ.get("THEMIS", "themis")
PROBE_URL = os.environ.get("THEMIS_PROBE_URL", "http://127.0.0.1:8080/health")
LOCK = os.environ.get("THEMIS_REATTACH_LOCK", "/run/themis-reattach.lock")
SETTLE_S = float(os.environ.get("THEMIS_SETTLE_S", "60"))


def log(msg: str) -> None:
    print(f"[themis-reattach] {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}", flush=True)


class _UnixConn(http.client.HTTPConnection):
    def __init__(self) -> None:
        super().__init__("localhost", timeout=60)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect("/var/run/docker.sock")


def api(method: str, path: str, body: dict | None = None, ok404: bool = False):
    conn = _UnixConn()
    try:
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
        resp = conn.getresponse()
        raw = resp.read()
        if resp.status == 404 and ok404:
            return None
        if resp.status >= 300 and resp.status != 304:
            raise RuntimeError(f"docker {method} {path.split('?')[0]} -> HTTP {resp.status}")
        return json.loads(raw) if raw else None
    finally:
        conn.close()


def probe() -> bool:
    """THEMIS as the hub sees it: a request from inside the hub's namespace."""
    code = ("import urllib.request,sys\n"
            f"sys.exit(0 if urllib.request.urlopen({PROBE_URL!r}, timeout=3).status == 200 else 1)")
    try:
        return subprocess.run(["docker", "exec", HUB, "python3", "-c", code],
                              capture_output=True, timeout=20).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def wait_reachable(seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(2)
    return False


def create_body(info: dict, hub_id: str) -> dict:
    """THEMIS's own config, with only the network moved to the live hub."""
    config = copy.deepcopy(info["Config"])
    host = copy.deepcopy(info["HostConfig"])
    config["Image"] = info["Image"]
    for key in ("Hostname", "Domainname", "ExposedPorts"):
        config.pop(key, None)  # refused or meaningless under container: networking
    host["Binds"] = []
    host["Mounts"] = [m for m in host.get("Mounts") or [] if m.get("Type") == "tmpfs"]
    for mount in info.get("Mounts") or []:
        if mount["Type"] == "tmpfs":
            continue
        source = mount.get("Name") if mount["Type"] == "volume" else mount["Source"]
        host["Binds"].append(f"{source}:{mount['Destination']}:{'rw' if mount['RW'] else 'ro'}")
    host["NetworkMode"] = f"container:{hub_id}"
    host.pop("PortBindings", None)
    config["HostConfig"] = host
    return config


def recreate(info: dict, hub_id: str) -> bool:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stranded = f"{THEMIS}-stranded-{stamp}"
    body = create_body(info, hub_id)
    api("POST", f"/containers/{info['Id']}/rename?name={stranded}")
    api("POST", f"/containers/{info['Id']}/stop?t=10")
    log(f"old THEMIS kept as {stranded} (stopped); creating {THEMIS} in hub {hub_id[:12]}")
    try:
        new = api("POST", f"/containers/create?name={THEMIS}", body)
        api("POST", f"/containers/{new['Id']}/start")
    except Exception as exc:  # put the old one back exactly as it was
        log(f"create failed ({exc}); restoring {stranded}")
        api("DELETE", f"/containers/{THEMIS}?force=1", ok404=True)
        api("POST", f"/containers/{info['Id']}/rename?name={THEMIS}")
        api("POST", f"/containers/{info['Id']}/start")
        return False
    if wait_reachable(SETTLE_S):
        api("DELETE", f"/containers/{info['Id']}?v=0")  # never the volumes
        log(f"recreated; reachable from the hub; removed {stranded}")
        return True
    log(f"new THEMIS not reachable after {SETTLE_S:.0f}s; restoring {stranded}")
    api("DELETE", f"/containers/{new['Id']}?force=1&v=0")
    api("POST", f"/containers/{info['Id']}/rename?name={THEMIS}")
    api("POST", f"/containers/{info['Id']}/start")
    return False


def reconcile() -> int:
    hub = api("GET", f"/containers/{HUB}/json", ok404=True)
    if not hub or not hub["State"]["Running"]:
        log(f"hub {HUB} not running; nothing to attach to")
        return 0
    themis = api("GET", f"/containers/{THEMIS}/json", ok404=True)
    if not themis:
        log(f"no container named {THEMIS}; not inventing one")
        return 1
    mode = themis["HostConfig"].get("NetworkMode", "")
    ref = mode.split(":", 1)[1] if mode.startswith("container:") else ""
    same_hub = bool(ref) and (ref == hub["Id"] or ref == HUB or hub["Id"].startswith(ref))
    if themis["State"]["Running"] and same_hub and probe():
        log(f"reachable from hub {hub['Id'][:12]}; ok")
        return 0
    if same_hub:
        log(f"THEMIS points at the live hub {hub['Id'][:12]} but is not reachable from it "
            f"(in-place hub restart strands it); restarting THEMIS")
        api("POST", f"/containers/{themis['Id']}/restart?t=10")
        ok = wait_reachable(SETTLE_S)
    else:
        log(f"THEMIS points at {ref[:12] or mode!r}, the live hub is {hub['Id'][:12]}; recreating")
        ok = recreate(themis, hub["Id"])
    log("reachable again" if ok else "STILL NOT REACHABLE")
    return 0 if ok else 1


def main() -> int:
    with open(LOCK, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)  # the event watcher and the timer never overlap
        return reconcile()


if __name__ == "__main__":
    sys.exit(main())
