# Secure Subscription Collector

`secure-subscription-collector` собирает URI профилей **VLESS**, **Trojan** и **Hysteria2** из публичных Telegram-каналов. Каналы находятся через seed-подписки в `input.txt`, затем оцениваются по наблюдаемым признакам качества. В итоговые файлы попадают только уникальные профили, прошедшие строгую статическую security policy, из каналов со статусом `approved`.

> Проект не запускает tunnel core, не делает проверку IP через профиль и не подтверждает сетевую доступность профиля. Пригодность профиля к подключению оператор проверяет самостоятельно в **v2rayNG** или ином доверенном клиенте.

Сборщик запрашивает только публичные preview-страницы `https://t.me/s/<username>`. Telegram API, авторизация, private invite-ссылки, CAPTCHA, обход ограничений платформы и сбор закрытых каналов не используются.

## Конвейер

```text
input.txt (HTTPS seed-подписки)
  -> public Telegram handle discovery
  -> t.me/s/<username> public preview, максимум 72 часа
  -> URI extraction and parser
  -> Strict Secure policy
  -> exact fingerprint deduplication
  -> content-quality gate for Telegram channel
  -> output/vless.txt, output/trojan.txt, output/hysteria2.txt
```

Seed URI нужны только для обнаружения публичных каналов и никогда не публикуются напрямую. Сбой одного канала изолирован: он не прекращает обработку остальных каналов.

## Публичные каналы и временное окно

Из raw URI, включая URL-кодированный fragment, извлекаются только явные публичные формы `@username`, `t.me/username`, `t.me/s/username`, `telegram.me/username` и `tg://resolve?domain=username`. Username нормализуется в lowercase и обязан соответствовать шаблону `[A-Za-z][A-Za-z0-9_]{4,31}`. Приватные invite-ссылки, `t.me/c/...`, bare words и некорректные имена исключаются.

Сообщение учитывается только при наличии `time[datetime]` и публикации в интервале `now_utc − 72 hours … now_utc`. Для одобренного канала сборщик идёт по контролируемому cursor `?before=<message_id>` и завершает чтение при пересечении временного окна, повторе cursor, недоступном preview или достижении `max_pages_per_channel`.

## Поддерживаемые профили и Strict Secure policy

| Протокол | Обязательные условия |
|---|---|
| VLESS | UUID; TLS с SNI и fingerprint либо Reality с `encryption=none`, SNI, fingerprint и валидным 32-байтовым `pbk`. |
| Trojan | Непустой пароль, TLS, SNI и fingerprint. |
| Hysteria2 / hy2 | Непустой пароль, TLS и SNI. |

Схемы вне указанной области, неподдерживаемые транспорты, а также профили с `allowInsecure=1`, `insecure=1`, `true` или `yes` исключаются. Валидация профиля является детерминированной: parser формирует структуру URI, policy проверяет обязательные security-поля, а deduplication удаляет только точные косметические дубликаты по каноническому SHA-256 fingerprint.

## Quality gate для Telegram-каналов

Оценка источника не зависит от сети CI-runner и вычисляется из редактированных агрегатов текущего публичного preview.

| Сигнал | Вес | Измерение |
|---|---:|---|
| Доступность preview | 15 | Preview был успешно прочитан и разобран. |
| Свежая активность | 20 | Число свежих постов относительно `min_fresh_posts`. |
| Доля поддерживаемых URI | 20 | Поддерживаемые распарсенные кандидаты / все URI-кандидаты. |
| Доля профилей, прошедших policy | 25 | Policy-accepted / поддерживаемые кандидаты. |
| Уникальность | 20 | Уникальные fingerprint / policy-accepted профили. |

| Статус | Условие | URI допускаются в output |
|---|---|---|
| `candidate` | Ещё не накоплено `min_evidence_runs` независимых наблюдений. | Нет |
| `approved` | Достаточно наблюдений, выполнены минимумы свежести и кандидатов, score не ниже `approval_score`. | Да |
| `excluded` | Достаточно наблюдений, но не выполнены content-пороги или score. | Нет |

Состояние каналов хранится в `.collector/channel_state.json` под SHA-256 ключом handle. Формат имеет версию `2`; записи старого формата не переносятся, потому что их статусы были основаны на удалённой сетевой проверке. При первой работе после обновления все каналы проходят новую content-only оценку.

## Итоговые файлы

| Путь | Содержимое |
|---|---|
| `output/vless.txt` | Уникальные VLESS из одобренных каналов, прошедшие strict policy. |
| `output/trojan.txt` | Уникальные Trojan из одобренных каналов, прошедшие strict policy. |
| `output/hysteria2.txt` | Уникальные Hysteria2/hy2 из одобренных каналов, прошедшие strict policy. |
| `tg_channels` | Все обнаруженные нормализованные публичные `@username`, включая `candidate` и `excluded`. |
| `.collector/state.json` | Время первого и последнего появления fingerprint для публикации. |
| `.collector/channel_state.json` | Обезличенное состояние качества каналов. |
| `report.json` | Только агрегированные метрики discovery, quality gate, publication и исключений. |

URI сохраняются в совместимом формате, но имя после `#` заменяется на короткий безопасный код, например `VL-REALITY-GRPC-3ScvEG`. Raw HTML, текст постов, полные URI, host, SNI, UUID, пароль и ключи не записываются в report, channel state или логи.

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

Все лимиты проверяются до сетевых запросов. `max_post_age_hours` не может превышать 72.

## Локальный запуск

Для запуска требуется Python и зависимости проекта; дополнительных tunnel binaries не требуется.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

PYTHONPATH=src python -m subscription_collector
PYTHONPATH=src ruff check .
PYTHONPATH=src pytest -q
```

Тесты используют mocked HTTP transport и не выполняют реальных запросов к Telegram или endpoint профилей.

## Автоматизация

Workflow запускается каждые четыре часа. Job `collect` имеет только `contents: read`, устанавливает Python-зависимости и выполняет content-quality pipeline. Только job `publish` имеет `contents: write` и коммитит ограниченный набор артефактов: `output/`, `report.json`, состояния и `tg_channels`.

Отдельный workflow тестирования запускает `ruff` и `pytest` для `push` и `pull_request`. Все сторонние Actions закреплены полными commit SHA.

## Профильный анализ и ограничения

В текущем проекте **нет ML-модели, training artifacts, inference или ML-зависимостей**. Термин «анализ профиля» означает детерминированный parser, strict security policy и exact deduplication; эти компоненты покрыты автоматическими положительными, отрицательными и регрессионными тестами.

Quality score измеряет технические признаки открытого источника в коротком окне. Он не гарантирует сетевую доступность, происхождение, безопасность, правовой статус или пригодность стороннего профиля в сети пользователя. Перед импортом и использованием профиля оператор обязан самостоятельно оценить его доверенность и подключаемость в своём клиенте.
