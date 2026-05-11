# SOLID Fix Log — adapstory-plugin-gateway

**Дата:** 2026-05-11
**Основание:** SOLID-AUDIT-REPORT.md
**Тесты:** 280 passed, 0 failed, 0 skipped

---

## Исправленные нарушения

### 1. [DRY/OCP HIGH #4] ProxyHeaderUtils — вынесено дублирование McpProxyService + ProxyExecutionService

**Проблема:** Посимвольное дублирование `HOP_BY_HOP_HEADERS`, `copyRequestHeaders()`, `copyResponse()` между `McpProxyService` и `ProxyExecutionService` (~42 строки).

**Решение:**
- Создан `util/ProxyHeaderUtils.java` — статический utility класс с:
  - `HOP_BY_HOP_HEADERS` — общий `Set.of(...)` констант
  - `copyRequestHeaders(HttpServletRequest, HttpHeaders)` — статический метод
  - `copyResponse(ClientHttpResponse, HttpServletResponse)` — статический метод
- `McpProxyService.java` — удалены локальные `HOP_BY_HOP_HEADERS`, `copyRequestHeaders()`, `copyResponse()`, вызовы заменены на `ProxyHeaderUtils.*`
- `ProxyExecutionService.java` — аналогично удалены дублированные методы и константа

**Файлы:**
- `util/ProxyHeaderUtils.java` (новый, 87 строк)
- `routing/McpProxyService.java` (изменён)
- `routing/ProxyExecutionService.java` (изменён, 94 строки)

---

### 2. [DRY/OCP HIGH #5] FetchClientUtils — вынесено дублирование InstalledPluginFetchClient + PermissionFetchClient

**Проблема:** Посимвольное дублирование `PLUGIN_ID_PATTERN`, `propagateHeader()`, fallback header interceptor lambda между двумя BC-02 клиентами (~60 строк).

**Решение:**
- Создан `util/FetchClientUtils.java` — статический utility класс с:
  - `PLUGIN_ID_PATTERN` — общий regex
  - `HEADER_SOURCE_SERVICE` — константа `"plugin-gateway"`
  - `propagateHeader(HttpRequest, String, String, String)` — статический метод
  - `fallbackHeaderInterceptor()` — фабричный метод для fallback-интерцептора
- `InstalledPluginFetchClient.java` — удалены `PLUGIN_ID_PATTERN`, `SOURCE_SERVICE`, `propagateHeader()`, inline fallback interceptor; используются `FetchClientUtils.*`
- `PermissionFetchClient.java` — аналогично; `validatePluginId()` использует `FetchClientUtils.PLUGIN_ID_PATTERN`

**Файлы:**
- `util/FetchClientUtils.java` (новый, 65 строк)
- `client/InstalledPluginFetchClient.java` (изменён)
- `client/PermissionFetchClient.java` (изменён, 190 строк)

---

### 3. [OCP MEDIUM #6] PluginSlugValidator — вынесено дублирование slug-валидации

**Проблема:** Одинаковый regex `^[a-zA-Z0-9][a-zA-Z0-9-]*$` в `McpRouteController.SLUG_PATTERN` и `WebhookDispatcher.PLUGIN_SHORT_ID_PATTERN`.

**Решение:**
- Создан `util/PluginSlugValidator.java` с:
  - `SLUG_PATTERN` — общий compiled pattern
  - `isValidSlug(String)` — статический метод
- `McpRouteController.java` — удалён `SLUG_PATTERN`, используется `PluginSlugValidator.isValidSlug()`
- `WebhookDispatcher.java` — удалён `PLUGIN_SHORT_ID_PATTERN`, используется `PluginSlugValidator.isValidSlug()`

**Файлы:**
- `util/PluginSlugValidator.java` (новый, 27 строк)
- `routing/McpRouteController.java` (изменён)
- `routing/WebhookDispatcher.java` (изменён)

---

### 4. [SRP LOW #10] SecurityConfig — обобщён шаблонный код disableAutoRegistration

**Проблема:** 5 идентичных методов `disableXxxAutoRegistration()` для каждого фильтра — нарушение OCP/SRP.

**Решение:**
- Добавлен generic helper `private <T extends OncePerRequestFilter> FilterRegistrationBean<T> disableAutoRegistration(T filter)`
- Все 5 `@Bean` методов делегируют в общий helper

**Файлы:**
- `config/SecurityConfig.java` (изменён, 168 строк)

---

### 5. [DIP LOW #13] PermissionEnforcementFilter — заменён `new` на injection

**Проблема:** В конструкторе фильтра создавался `new PermissionIntersectionService(properties, permissionCacheService)` вместо Spring DI.

**Решение:**
- `PermissionIntersectionService` помечен как `@Component`
- Конструктор `PermissionEnforcementFilter` теперь принимает `PermissionIntersectionService intersectionService` напрямую через injection
- Удалены неиспользуемые импорты `GatewayProperties` и `PermissionCacheService` из фильтра

**Файлы:**
- `filter/PermissionIntersectionService.java` (добавлен `@Component`)
- `filter/PermissionEnforcementFilter.java` (изменён конструктор)
- `test/.../PermissionEnforcementFilterTest.java` (обновлён — `new PermissionIntersectionService(...)` в setUp)

---

## Статистика изменений

| Метрика | До | После |
|---------|----|-------|
| Новые utility-классы | 0 | 3 (`ProxyHeaderUtils`, `FetchClientUtils`, `PluginSlugValidator`) |
| Дублированных строк кода | ~104 | 0 |
| Файлов с `new` вместо DI | 1 (`PermissionEnforcementFilter`) | 0 |
| Дублированных regex-паттернов | 2 (SLUG, PLUGIN_ID) | 0 |
| Дублированных констант HOP_BY_HOP_HEADERS | 2 | 0 |
| Тестов | 280 passed | 280 passed |

---

## Не исправлено (LOW priority, requires more invasive changes)

| # | Нарушение | Причина откладывания |
|---|-----------|---------------------|
| 7 | IntersectionResult → sealed interface | Требует изменения всех callers на switch pattern matching; Java 21+ feature; низкий приоритет |
| 8 | McpProxyService — urlOverrides для тестов | Требует переписывания тестов на WireMock/@MockBean; средний риск |
| 9 | McpRouteController — делегирующие методы | Зависит от #8 (overridePluginUrl); убираем вместе |
| 11 | InstalledPluginCacheService — nullable callbacks | Требует изменения metric interface; низкий приоритет |
| 12 | PluginAuthFilter — JWT processor config | Требует создания JwtProcessorConfig; средний приоритет |
| 14-15 | Port-интерфейсы для fetch clients | Требует создания интерфейсов + обновления всех consumers; высокий объём |
| 16 | WebhookDispatcher — разделить controller + service | Значительный рефакторинг; средний приоритет |
| 17 | PermissionCacheInvalidationListener — Spring Kafka привязка | Стандартный Spring паттерн; LOW severity |
| 18 | GatewayProperties — ISP разделение | Приемлемо для gateway с единым namespace; LOW severity |
