# Secure Subscription Collector

`secure-subscription-collector` собирает профили **VLESS**, **Trojan** и **Hysteria2** из публичных Telegram-каналов, обнаруженных через seed-подписки в `input.txt`. Итоговые protocol-файлы содержат только URI из каналов с подтверждённым качеством, прошедшие строгую policy, точную дедупликацию и текущую Xray IP-проверку.

> Проект запрашивает только публичные preview-страницы `https://t.me/s/<username>`. Telegram API, авторизация, private invite-ссылки, CAPTCHA, обход ограничений платформы и сбор закрытых каналов не используются.

## Конвейер

```text
input.txt (HTTPS seed-подписки)
  → raw VLESS/Trojan/Hysteria2 URI
  → явные public Telegram handle
  → tg_channels
  → t.me/s/<username>, только последние 72 часа
  → score канала и candidate/approved/excluded
  → строгая policy → exact deduplication → Xray IP validation
  → output/vless.txt, output/trojan.txt, output/hysteria2.txt
```

Seed URI нужны только для discovery и **не публикуются напрямую**. Сбой одного канала не прекращает обработку остальных.

## Допустимые каналы и временное окно

Из полного raw URI, в том числе из URL-кодированного fragment, принимаются только явные публичные формы `@username`, `t.me/username`, `t.me/s/username`, `telegram.me/username` и `tg://resolve?domain=username`. Username обязан соответствовать `[A-Za-z][A-Za-z0-9_]{4,31}` и записывается в lowercase. `t.me/+…`, `joinchat`, `t.me/c/...`, bare words и некорректные имена отбрасываются.

Сообщение учитывается только при наличии `time[datetime]` и публикации в интервале `now_utc − 72 hours … now_utc`. Для уже одобренного канала сборщик использует контролируемый cursor `?before=<message_id>` и останавливается, когда окно пересечено, cursor повторился, достигнут `max_pages_per_channel` или preview перестал быть доступен.

## Поддерживаемые профили и security policy

| Протокол | Условие strict policy |
|---|---|
| VLESS | UUID; TLS с SNI и fingerprint либо Reality с `encryption=none`, SNI, fingerprint и валидным `pbk` |
| Trojan | Пароль, TLS, SNI и fingerprint |
| Hysteria2 / `hy2` | Пароль, TLS и SNI |

Схемы вне области проекта и профили с `allowInsecure=1` либо `insecure=1` исключаются. Для каждого кандидата создаётся временная Xray-конфигурация с SOCKS-входом на `127.0.0.1`; в output попадает URI, подтвердивший соединение через свой Xray outbound. Временные Xray-процессы и JSON удаляются после попытки.

## Quality gate

| Статус | Условие | URI допускаются в output |
|---|---|---|
| `candidate` | Меньше двух независимых оценок | Нет |
| `approved` | Не менее двух оценок, score ≥55, не менее двух поддерживаемых URI и есть фактический Xray-успех | Да |
| `excluded` | Достаточно evidence, но пороги не выполнены либо нет Xray-успеха | Нет |

Score 0–100 состоит из доступности preview (10%), активности за 72 часа (10%), доли поддерживаемых URI (15%), strict policy (20%), уникальности (15%), Xray viability с beta-smoothing (20%) и исторической стабильности (10%). Начальный beta-prior `alpha=1`, `beta=1` не даёт единичному результату исказить score. `excluded` не активируется автоматически: для ручной переоценки оператор удаляет нужную запись из `.collector/channel_state.json` и ждёт два новых запуска.

## Файлы результата

| Путь | Содержимое |
|---|---|
| `output/vless.txt` | Только Xray-validated VLESS из approved каналов |
| `output/trojan.txt` | Только Xray-validated Trojan из approved каналов |
| `output/hysteria2.txt` | Только Xray-validated Hysteria2/`hy2` из approved каналов |
| `tg_channels` | Один нормализованный публичный `@username` на строку; все discovered каналы, включая excluded |
| `.collector/state.json` | История profile fingerprint и времени наблюдения |
| `.collector/channel_state.json` | Обезличенное quality state, индексированное SHA-256 handle |
| `report.json` | Только агрегированные seed, Telegram, policy, Xray и publication metrics |

URI в `output/` сохраняются в совместимом формате, но отображаемое имя после `#` заменяется на безопасный короткий код наподобие `VL-REALITY-GRPC-3ScvEG`. Raw HTML, текст постов, полный URI, host, SNI, UUID, пароль и ключи не пишутся в report, channel state или логи; они существуют только во временной памяти текущего запуска и в намеренно опубликованных protocol-файлах.

## Конфигурация

`input.txt` содержит по одному публичному HTTPS URL seed-подписки на строку. Комментарии и дубликаты игнорируются; HTTP, malformed URL и URL с учётными данными отклоняются.

```yaml
telegram:
  registry: tg_channels
  state: .collector/channel_state.json
  max_post_age_hours: 72
  concurrency: 4
  timeout_seconds: 15.0
  max_response_bytes: 2097152
  max_redirects: 2
  max_pages_per_channel: 8
  sample_post_limit: 25

channel_quality:
  approval_score: 55.0
  min_evidence_runs: 2
  min_supported_candidates: 2
  min_fresh_posts: 2
```

Все лимиты валидируются до сетевых запросов; `max_post_age_hours` не может превышать 72.

## Локальный запуск и проверка

Для полного локального запуска требуется Xray binary. В CI версия читается из `config.yaml`, официальный архив проверяется по SHA-512 из release `.dgst`.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

PYTHONPATH=src python -m subscription_collector --xray-path /absolute/path/to/xray
PYTHONPATH=src ruff check .
PYTHONPATH=src pytest -q
```

Тесты не выполняют реальные HTTP-запросы и не используют реальные profile credentials. Xray-интеграционные тесты явно пропускаются, пока не задан `XRAY_TEST_BINARY`.

## GitHub Actions

Плановый workflow запускается каждые четыре часа. Job `collect` имеет только `contents: read`, запускает pipeline и передаёт строго ограниченные артефакты. Только job `publish` обладает `contents: write` и коммитит:

```text
output/
report.json
.collector/state.json
.collector/channel_state.json
tg_channels
```

Отдельный workflow `Test collector` запускает `ruff` и `pytest` на `push` и `pull_request`. Все сторонние Actions закреплены на полных commit SHA.

## Ограничения

Технический score измеряет только наблюдаемое качество публичного источника в коротком окне. Он не гарантирует доступность, безопасность, происхождение, правовой статус или пригодность стороннего профиля в сети пользователя. Успешная Xray-проверка подтверждает работоспособность из сети runner на момент запуска; решение об импорте и использовании профиля остаётся за оператором.
