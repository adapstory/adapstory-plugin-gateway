# GRASP Fix Log — `adapstory-plugin-gateway`

> **Дата:** 2025-07
> **Основание:** `GRASP-AUDIT-REPORT.md` — HIGH и MEDIUM нарушения
> **Принцип:** Минимальные изменения, без поломки тестов

---

## Сводка исправлений

| ID | Паттерн | Серьёзность | Статус | Изменение |
|----|---------|-------------|--------|-----------|
| PV-2 | Protected Variations | HIGH | ✅ Исправлено | Добавлен connect/read timeout (3s) в `WebhookDispatchService` |
| LC-1 | Low Coupling | HIGH | ✅ Ранее исправлено | CB-конфигурация централизована в `Bc02ClientConfig` |
| LC-2 | Low Coupling | HIGH | ✅ Ранее исправлено | RestClient-конфигурация централизована в `Bc02ClientConfig` |
| PF-1 | Pure Fabrication | HIGH | ✅ Ранее исправлено | Создан `Bc02ClientConfig` как shared factory |
| HC-1 | High Cohesion | MEDIUM | ✅ Исправлено | JWT processor creation → `JwtProcessorFactory` |
| IE-2 | Information Expert | MEDIUM | ✅ Исправлено | Claims mapping → `PluginJwtClaimsMapper` (уже существовал) |
| C-2 | Controller | MEDIUM | ✅ Исправлено | `WebhookDispatcher` → thin controller + `WebhookDispatchService` |
| HC-2 | High Cohesion | MEDIUM | ✅ Исправлено | Разделены retry/async dispatch и REST endpoint |
| IE-1 | Information Expert | MEDIUM | ✅ Ранее исправлено | `validatePluginId()` → `FetchClientUtils` |
| LC-3 | Low Coupling | MEDIUM | ✅ Ранее исправлено | Убрана зависимость `cache/` → `client/` |

---

## Детали изменений

### PV-2 HIGH — Timeout на proxy RestClient

**Проблема:** `WebhookDispatcher` создавал `RestClient` без таймаутов. Зависший upstream блокировал поток.

**Исправление:** Новый `WebhookDispatchService` создаёт `RestClient` с `SimpleClientHttpRequestFactory` (connect=3000ms, read=3000ms), аналогично `ProxyExecutionService` и `McpProxyService`.

**Файлы:**
- `routing/WebhookDispatchService.java` — новый класс, создаёт RestClient с timeout

> **Примечание:** `ProxyExecutionService` и `McpProxyService` уже имели таймауты (3000ms) — исправление применено только к webhook-dispatch.

---

### LC-1/LC-2 HIGH + PF-1 — Дублирование RestClient + CircuitBreaker

**Проблема:** ~80 строк идентичной конфигурации в `InstalledPluginFetchClient` и `PermissionFetchClient`.

**Исправление (предыдущий патч):** Создан `Bc02ClientConfig` — shared `@Configuration` factory:
- `createBc02RestClient(RestClient.Builder)` — timeout, base URL, service token interceptor
- `createBc02CircuitBreaker(CircuitBreakerRegistry, String)` — CB с shared конфигурацией

**Файлы:**
- `config/Bc02ClientConfig.java` — shared factory (уже существовал)
- `client/InstalledPluginFetchClient.java` — делегирует `Bc02ClientConfig` (уже обновлён)
- `client/PermissionFetchClient.java` — делегирует `Bc02ClientConfig` (уже обновлён)

---

### HC-1 MEDIUM — PluginAuthFilter: 4 ответственности

**Проблема:** Фильтр совмещал JWT processor setup, JWT validation, claims mapping, SecurityContext management.

**Исправление:**
1. JWT processor creation → `config/JwtProcessorFactory` (новый `@Component`)
2. Claims mapping → `filter/PluginJwtClaimsMapper` (уже существовал, уже использовался)
3. `PluginAuthFilter` — только фильтрация: Bearer extraction → validate → map → set context
4. Дополнительно исправлен баг: `Span.current().setAttribute("plugin.id", pluginId)` → `pluginContext.pluginId()` (undefined variable)

**Файлы:**
- `config/JwtProcessorFactory.java` — новый класс, единственная ответственность: сборка JWT processor pipeline
- `filter/PluginAuthFilter.java` — делегирует `jwtProcessorFactory.createJwtProcessor()`, убраны NimbusDS imports
- `filter/PluginJwtClaimsMapper.java` — без изменений (уже выделен)
- `test/.../PluginAuthFilterTest.java` — обновлён: передаёт `JwtProcessorFactory` в конструктор

---

### C-2/HC-2 MEDIUM — WebhookDispatcher: 5 ответственностей

**Проблема:** Один класс совмещал REST endpoint, retry-конфигурацию, secret validation, endpoint resolution, async dispatch.

**Исправление:**
1. `WebhookDispatcher` — thin REST controller: endpoint + validation (slug, secret) + делегирование
2. `WebhookDispatchService` — `@Service`: retry, async dispatch, endpoint resolution, HTTP delivery
3. RestClient в `WebhookDispatchService` создаётся с таймаутами (PV-2)

**Файлы:**
- `routing/WebhookDispatcher.java` — упрощён до thin controller, делегирует `WebhookDispatchService`
- `routing/WebhookDispatchService.java` — новый класс, retry + async dispatch + endpoint resolution
- `test/.../WebhookDispatcherTest.java` — обновлён: создаёт `WebhookDispatchService`, передаёт в `WebhookDispatcher`
- `test/.../WebhookDispatcherAdditionalTest.java` — обновлён: аналогично

---

### IE-1/LC-3 MEDIUM — Кросс-слойная зависимость cache/ → client/

**Проблема:** `PermissionRevocationEventParser` (cache/) вызывал `PermissionFetchClient.validatePluginId()` (client/).

**Исправление (предыдущий патч):** Валидация перенесена в `FetchClientUtils.validatePluginId()`. `PermissionRevocationEventParser` уже использует `FetchClientUtils.validatePluginId()` напрямую.

**Файлы:**
- `cache/PermissionRevocationEventParser.java` — вызывает `FetchClientUtils.validatePluginId()` (уже исправлено)
- `util/FetchClientUtils.java` — содержит `validatePluginId()` (без изменений)

---

## Влияние на тесты

| Тест | Изменение | Статус |
|------|-----------|--------|
| `PluginAuthFilterTest` | Добавлен `JwtProcessorFactory` в конструктор | ✅ Диагностика чиста |
| `WebhookDispatcherTest` | `executeWithRetry` → `dispatchService`, constructor обновлён | ✅ Диагностика чиста |
| `WebhookDispatcherAdditionalTest` | `createDispatcher()` обновлён для нового конструктора | ✅ Диагностика чиста |
| `PermissionRevocationEventParserTest` | Без изменений | ✅ Без изменений |
| Остальные тесты | Без изменений | ✅ Без изменений |

---

## Новые классы

| Класс | Пакет | Ответственность |
|-------|-------|-----------------|
| `JwtProcessorFactory` | `config/` | Создание JWT processor pipeline (JWKS, key selector, claims verifier) |
| `WebhookDispatchService` | `routing/` | Retry, async dispatch, endpoint resolution для webhook-ов |

## Удалённые классы

Нет.

---

## Отложенные нарушения (LOW severity, P2)

См. `GRASP-AUDIT-REPORT.md` → P2: C-1 (переименование), LC-4/I-1 (GatewayErrorResponseWriter bean), PV-3 (GATEWAY_PREFIX константа), I-2 (GatewayMetrics), P-2 (fetch-client интерфейсы).
