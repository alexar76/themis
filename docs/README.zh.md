# THEMIS

<p align="center">
  <img src="screenshots/hero.jpg" alt="THEMIS — AIMarket 发布准入门控" width="900">
</p>

[English](../README.md) · [Русский](README.ru.md) · [Español](README.es.md) · [Français](README.fr.md) · **中文** ·
[术语表](https://github.com/alexar76/aicom/blob/main/docs/localization-glossary.md) ·
[完整教程](https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.zh.md)

**是否应允许该 AI 智能体进入业务？** THEMIS 是 AIMarket 的**发布准入**（publish admission）门控：
基于可验证输入给出签名裁定 `approve` / `review` / `reject`。它**不是** Metis（认知），也**不是**
WARDEN（运行时）。

## 图库

以下为本地控制台 [`/ui/`](http://127.0.0.1:8080/ui/) 在真实 `/invoke` 后的截图
（safe → **approve**，unsafe → **reject**）。Capability：`agent.security.supply-chain.audit@v1`。

**公开仪表盘：** [落地页](https://alexar76.github.io/themis/) · [控制台](https://alexar76.github.io/themis/console/) · [Alien Monitor](https://magic-ai-factory.com/monitor/)

<table>
  <tr>
    <td width="50%"><img src="screenshots/report-approve.jpg" alt="THEMIS 准入收据 — APPROVE"></td>
    <td width="50%"><img src="screenshots/report-reject.jpg" alt="THEMIS 准入收据 — REJECT"></td>
  </tr>
  <tr>
    <td align="center"><strong>Approve · score 100</strong></td>
    <td align="center"><strong>Reject · fail-closed</strong></td>
  </tr>
  <tr>
    <td width="50%"><img src="screenshots/invoke-approve.svg" alt="原始 /invoke approve"></td>
    <td width="50%"><img src="screenshots/invoke-reject.svg" alt="原始 /invoke reject"></td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="screenshots/roles-split.jpg" alt="THEMIS · WARDEN · Metis" width="900">
    </td>
  </tr>
</table>

## 为何需要此智能体

接入的智能体可能执行代码、读取密钥、花费资金、写入外部系统，或依赖未审查的工具。OWASP Agentic
Top 10 明确覆盖身份与权限滥用、**AI 智能体供应链**漏洞、不安全的智能体间通信、级联故障，以及
人机信任被利用。

服务接受候选清单、声明的权限、evidence、预期用量与买方策略，并返回：

- `approve`、`review` 或 `reject`；
- 确定性分数与风险等级；
- 预计月成本；
- 具体发现与修复建议；
- OWASP Agentic Top 10 映射；
- 可选的异步 Metis 报告验证；
- 与请求绑定的 Ed25519 签名（**收据**）。

它不做合规认证，也不预测未来行为。当 Hub 模式开启时，THEMIS 成为进入公共目录前的**发布准入**。
上架本身已是多层路径（运营方 token、stake、清单、签名）——不是开放注册。通过 ARGUS /
`aimarket-mcp` **消费**生态不需要 THEMIS。
[准入说明](https://github.com/alexar76/themis/blob/main/docs/admission/zh.md)。

Capability `agent.security.supply-chain.audit@v1` 返回绑定精确 input 的签名收据。

## 工作方式

```text
清单 + 权限 + evidence + 用量 + 策略
                         │
                         ▼
             确定性审计
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
立即签名裁定                     延迟 Metis 任务
approve / review / reject        pending → completed
```

Metis 只审查报告内部一致性，永不覆盖确定性裁定。

## 快速开始

```bash
git clone https://github.com/alexar76/themis.git
cd themis
uv sync --extra dev
uv run python configure_provider.py
uv run python -m pytest -q
uv run python agent.py
```

另开终端：

```bash
curl --fail-with-body -sS \
  -X POST http://127.0.0.1:8080/invoke \
  -H 'Content-Type: application/json' \
  --data-binary @examples/safe_candidate.json
```

安全样例返回 `decision: approve`。将 `invoke_url` 改为公网 HTTP，或在无人工批准时启用
`execute_code`，应 fail-closed 为 `reject`。

## 输入约定

| 块 | 含义 |
|---|---|
| `candidate` | 被审查的 AIMarket 提供方清单 |
| `permissions` | 代码、密钥、资金、外部写入、网络、个人数据 |
| `evidence` | HTTPS 引用（SBOM、安全策略、独立审计） |
| `usage` | 每月调用量与数据分级 |
| `policy` | 价格、预算、身份、evidence 与验证要求 |
| `request_metis` | 启动 Metis 且不阻塞主裁定 |

未知字段一律拒绝。evidence URL **不会**被拉取，因此无法变成 SSRF 代理。

## 延迟 Metis

将 `.env.example` 复制为 `.env`，仅在服务器设置 `METIS_API_KEY`。当 `request_metis: true` 时，
`/invoke` 立即返回 `status: pending`、`verification_id` 与 `poll_url`。轮询
`GET /verification/{verification_id}`，直至 `completed`、`not_performed`、`timeout`、
`unavailable` 或 `failed`。

`assessment_verified` 表示 Metis 验证了自己的答复，并不表示候选方已被「验证」。

## 安全边界

- 请求体上限 256 KiB；
- 拒绝重复 JSON 键与未知字段；
- 解析但不访问输入 URL；
- 提供方私钥权限 `0600`；
- 签名覆盖精确 input 与结果；
- Metis 凭据仅留在服务器；
- Metis 任务有容量、并发、超时与 TTL 硬限制；
- 容器非 root；
- 认证与计费归属 Hub 或 ingress。

## 发布与 Alien Monitor

部署后设置公开 HTTPS `invoke_url` 与稳定 `publisher_id`：

```bash
uv run python configure_provider.py
uv run python validate_manifest.py
aimarket publish capability.json --hub https://modelmarket.dev
```

经 Hub 真实调用后，准入遥测会出现在 Alien Monitor 的 **THEMIS** 节点（Hub
`GET /supply/audits` 的无 dossier 收据）。本仓库不会从未认证客户端自行注入永久 3D 节点。

[用教程自行重建项目](https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.zh.md)。
