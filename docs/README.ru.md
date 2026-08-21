# THEMIS

<p align="center">
  <img src="screenshots/hero.jpg" alt="THEMIS — шлюз допуска публикации AIMarket" width="900">
</p>

[English](../README.md) · **Русский** · [Español](README.es.md) · [Français](README.fr.md) · [中文](README.zh.md) ·
[Глоссарий](https://github.com/alexar76/aicom/blob/main/docs/localization-glossary.md) ·
[Полный урок](https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.ru.md)

**Следует ли разрешить этому AI-агенту работать внутри бизнеса?** THEMIS — **шлюз допуска
публикации** (publish admission) для AIMarket: подписанное решение `approve` / `review` /
`reject` по проверяемым входам. Это **не** Metis (познание) и **не** WARDEN (runtime).

## Галерея

Карточки и сырой JSON ниже — от живого локального `/invoke` по `examples/safe_candidate.json`
(**approve**, score `100`) и fail-closed мутации (**reject**). Capability:
`agent.security.supply-chain.audit@v1`.

<table>
  <tr>
    <td width="50%"><img src="screenshots/report-approve.jpg" alt="Квитанция допуска THEMIS — APPROVE"></td>
    <td width="50%"><img src="screenshots/report-reject.jpg" alt="Квитанция допуска THEMIS — REJECT"></td>
  </tr>
  <tr>
    <td align="center"><strong>Approve · score 100</strong></td>
    <td align="center"><strong>Reject · fail-closed</strong></td>
  </tr>
  <tr>
    <td width="50%"><img src="screenshots/invoke-approve.svg" alt="Сырой /invoke approve"></td>
    <td width="50%"><img src="screenshots/invoke-reject.svg" alt="Сырой /invoke reject"></td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="screenshots/roles-split.jpg" alt="THEMIS · WARDEN · Metis" width="900">
    </td>
  </tr>
</table>

## Зачем нужен этот агент

Подключаемый агент может исполнять код, читать секреты, тратить деньги, менять внешние системы или
зависеть от непроверенных инструментов. OWASP Agentic Top 10 отдельно описывает злоупотребление
идентичностью и привилегиями, уязвимости **цепочки поставок AI-агентов**, небезопасное межагентное
взаимодействие, каскадные сбои и эксплуатацию доверия человека к агенту.

Сервис принимает манифест кандидата, заявленные полномочия, evidence, ожидаемую нагрузку и политику
покупателя. На выходе:

- `approve`, `review` или `reject`;
- детерминированная оценка и уровень риска;
- прогноз месячных расходов;
- конкретные находки и способы исправления;
- сопоставление с OWASP Agentic Top 10;
- необязательная асинхронная верификация отчёта через Metis;
- привязанная к запросу подпись Ed25519 (**квитанция**).

Это средство поддержки решения, а не сертификат соответствия и не доказательство будущего поведения
кандидата. При включённом режиме Hub THEMIS становится **допуском публикации** до публичного
каталога. Листинг уже многослойный (токен оператора, стейк, манифест, подписи) — не open signup.
**Потребление** через ARGUS / `aimarket-mcp` THEMIS не требует.
[Допуск EN/RU](https://github.com/alexar76/aicom/blob/main/docs/ecosystem/supply-chain-admission-ru.md).

Capability `agent.security.supply-chain.audit@v1` возвращает подписанную квитанцию, привязанную к
точному input.

## Как устроено

```text
манифест + полномочия + evidence + нагрузка + политика
                         │
                         ▼
             детерминированный аудит
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
подписанное решение сразу        ленивый запрос к Metis
approve / review / reject        pending → completed
```

Metis проверяет внутреннюю согласованность отчёта, но никогда не меняет основное решение.

## Быстрый старт

```bash
git clone https://github.com/alexar76/themis.git
cd themis
uv sync --extra dev
uv run python configure_provider.py
uv run python -m pytest -q
uv run python agent.py
```

Во втором терминале:

```bash
curl --fail-with-body -sS \
  -X POST http://127.0.0.1:8080/invoke \
  -H 'Content-Type: application/json' \
  --data-binary @examples/safe_candidate.json
```

Безопасный пример вернёт `decision: approve`. Замените `invoke_url` на публичный HTTP или разрешите
`execute_code` без человеческого подтверждения — агент должен перейти в fail-closed `reject`.

## Контракт

| Блок | Назначение |
|---|---|
| `candidate` | Манифест рассматриваемого поставщика AIMarket |
| `permissions` | Код, секреты, деньги, внешняя запись, сеть и персональные данные |
| `evidence` | HTTPS-ссылки на SBOM, политику безопасности или независимый аудит |
| `usage` | Месячное число вызовов (invoke) и классификация данных |
| `policy` | Ограничения цены, бюджета, идентичности, evidence и верификации |
| `request_metis` | Запустить Metis без блокировки основного решения |

Неизвестные поля отклоняются. URL из evidence не загружаются, поэтому сервис нельзя превратить в
SSRF-прокси.

## Ленивый Metis

Скопируйте `.env.example` в `.env` и задайте `METIS_API_KEY` только на сервере. При
`request_metis: true` основной вызов немедленно возвращает `status: pending`, `verification_id` и
`poll_url`. Запрашивайте `GET /verification/{verification_id}` до статуса `completed`,
`not_performed`, `timeout`, `unavailable` или `failed`.

`assessment_verified` означает, что Metis верифицировал собственный ответ. Это не означает, что
кандидат получил статус «верифицированный».

## Граница безопасности

- тело запроса ограничено 256 КиБ;
- повторяющиеся JSON-ключи и неизвестные поля отклоняются;
- входные URL разбираются, но не запрашиваются;
- закрытый ключ поставщика хранится с правами `0600`;
- подпись покрывает точный input и результат;
- ключ Metis остаётся на сервере;
- jobs Metis ограничены по размеру очереди, параллельности, timeout и TTL;
- контейнер работает без root;
- аутентификация, биллинг и внешние rate limits принадлежат Hub или ingress.

## Публикация и Alien Monitor

После деплоя укажите публичный HTTPS `invoke_url`, стабильный `publisher_id`, затем выполните:

```bash
uv run python configure_provider.py
uv run python validate_manifest.py
aimarket publish capability.json --hub https://modelmarket.dev
```

После реального вызова через Hub телеметрия допуска появляется на узле Alien Monitor **THEMIS**
(обезличенные квитанции Hub `GET /supply/audits`). Репозиторий не добавляет себе постоянную
3D-ноду напрямую: для неё нужен доверенный реестр.

[Пройдите подробный урок и пересоберите проект самостоятельно](https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.ru.md).
