from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

import configure_provider
import validate_manifest
from provider_signing import ProviderSigner

ROOT = Path(__file__).resolve().parents[1]


def test_configure_and_validate_manifest_atomically(tmp_path, monkeypatch):
    manifest = tmp_path / "capability.json"
    manifest.write_text((ROOT / "capability.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / ".aimarket/provider.key"))
    assert configure_provider.main() == 0
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(data["provider_pubkey"]) == 44
    assert validate_manifest.main() == 0
    assert not manifest.with_suffix(".json.tmp").exists()


def test_configure_removes_temporary_file_when_replace_fails(tmp_path, monkeypatch):
    manifest = tmp_path / "capability.json"
    manifest.write_text((ROOT / "capability.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / ".aimarket/provider.key"))
    original_replace = Path.replace

    def broken_replace(self, target):
        if self.name == "capability.json.tmp":
            raise OSError("simulated atomic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", broken_replace)
    with pytest.raises(OSError, match="simulated"):
        configure_provider.main()
    assert not manifest.with_suffix(".json.tmp").exists()


def test_provider_identity_is_persistent_and_private(tmp_path, monkeypatch):
    key = tmp_path / "identity" / "provider.key"
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    first = ProviderSigner()
    second = ProviderSigner()
    assert first.public_key_b64 == second.public_key_b64
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


@pytest.mark.parametrize("content", [b"short", b"x" * 33])
def test_corrupted_provider_identity_fails_closed(tmp_path, monkeypatch, content):
    key = tmp_path / "provider.key"
    key.write_bytes(content)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    with pytest.raises(RuntimeError, match="corrupted"):
        ProviderSigner()


def test_provider_identity_rejects_symlink(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_bytes(b"x" * 32)
    key = tmp_path / "provider.key"
    key.symlink_to(target)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    with pytest.raises(RuntimeError, match="regular file"):
        ProviderSigner()


def test_provider_identity_rejects_symlink_parent(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(linked / "provider.key"))
    with pytest.raises(RuntimeError, match="directory"):
        ProviderSigner()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.pop("provider_pubkey"), "missing required fields"),
        (lambda data: data.update(product_id="bad id"), "product_id must be"),
        (lambda data: data.update(capability_id="bad"), "capability_id must look"),
        (lambda data: data.update(publisher_id="tx-consumed:bad"), "reserved Hub"),
        (lambda data: data.update(invoke_url="http://example.com/invoke"), "must use HTTPS"),
        (lambda data: data.update(price_per_call_usd=float("inf")), "finite number"),
        (lambda data: data.update(input_schema=[]), "JSON object schema"),
        (lambda data: data.update(provider_pubkey="bad"), "canonical base64"),
    ],
)
def test_manifest_validator_fails_closed(tmp_path, monkeypatch, mutation, message):
    data = json.loads((ROOT / "capability.json").read_text(encoding="utf-8"))
    data["provider_pubkey"] = "A" * 43 + "="
    mutation(data)
    (tmp_path / "capability.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match=message):
        validate_manifest.main()


def test_manifest_reader_rejects_duplicate_keys_and_large_files(tmp_path, monkeypatch):
    path = tmp_path / "capability.json"
    monkeypatch.chdir(tmp_path)
    path.write_text('{"product_id":"a","product_id":"b"}', encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicate key"):
        validate_manifest.read_manifest()
    path.write_text(" " * (validate_manifest.MAX_MANIFEST_BYTES + 1), encoding="utf-8")
    with pytest.raises(SystemExit, match="exceeds"):
        validate_manifest.read_manifest()


def test_manifest_reader_rejects_missing_symlink_invalid_json_and_non_object(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match="cannot inspect"):
        validate_manifest.read_manifest()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    path = tmp_path / "capability.json"
    path.symlink_to(target)
    with pytest.raises(SystemExit, match="regular file"):
        validate_manifest.read_manifest()
    path.unlink()
    path.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="not valid"):
        validate_manifest.read_manifest()
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit, match="one JSON object"):
        validate_manifest.read_manifest()


@pytest.mark.parametrize("value", [True, "not-a-number"])
def test_manifest_finite_number_rejects_bool_and_text(value):
    with pytest.raises(SystemExit, match="finite number"):
        validate_manifest.finite_number({"x": value}, "x", minimum=0, maximum=1)


@pytest.mark.parametrize(
    ("url", "message"),
    [
        (123, "absolute"),
        ("https://example.com:99999/invoke", "malformed"),
        ("/relative", "absolute"),
        ("https://user:pass@example.com/invoke", "credentials"),
        ("https://example.com/invoke?secret=x", "query string"),
    ],
)
def test_manifest_url_validation_edges(url, message):
    with pytest.raises(SystemExit, match=message):
        validate_manifest.validate_invoke_url(url)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "", "missing required"),
        ("publisher_id", "bad publisher", "publisher_id must"),
        ("provider_pubkey", "YQ==", "exactly 32"),
    ],
)
def test_manifest_validator_more_invalid_fields(tmp_path, monkeypatch, field, value, message):
    data = json.loads((ROOT / "capability.json").read_text(encoding="utf-8"))
    data["provider_pubkey"] = "A" * 43 + "="
    data[field] = value
    (tmp_path / "capability.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match=message):
        validate_manifest.main()
