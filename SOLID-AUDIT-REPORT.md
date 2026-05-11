# SOLID Audit Report: adapstory-plugin-gateway

**Дата аудита:** 2025-07-14  
**Аудитор:** Automated SOLID Auditor  
**Микросервис:** adapstory-plugin-gateway (Plugin Gateway — REST-прокси для взаимодействия плагинов с core BC)  
**Всего исходных файлов (main):** 30 Java-классов  
**Всего нарушений:** 18

---

## Сводная таблица

| # | Файл | Принцип | Серьёзность | Описание |
|---|------|---------|-------------|----------|
| 1 | `InstalledPluginFetchClient.java` | **SRP** | HIGH | 247 строк — превышение лимита 200 строк; 6 зависимостей в конструкторе + смешивает RestClient wire-config, CB-config, header propagation и HTTP dispatch |
| 2 | `McpProxyService.java` | **SRP** | HIGH | 254 строки — превышение лимита 200 строк; совмещает URL resolution, header copying, response streaming, MCP method extraction, test URL overrides |
| 3 | `PermissionEnforcementFilter.java` | **SRP** | MEDIUM | 208 строк — превышение лимита 200 строк для command handler / filter; смешивает HTTP filter mechanics + error formatting + metric recording |
| 4 | `McpProxyService.java` + `ProxyExecutionService.java` | **DRY / OCP** | HIGH | Полное дублирование `HOP_BY_HOP_HEADERS`, `copyRequestHeaders()`, `copyResponse()` — 3 метода и константа дублированы почти посимвольно |
| 5 | `InstalledPluginFetchClient.java` + `PermissionFetchClient.java` | **DRY / OCP** | HIGH | Полное дублирование `PLUGIN_ID_PATTERN`, `propagateHeader()`, fallback header interceptor lambda, RestClient wiring logic — ~60 строк дублированного кода |
| 6 | `McpRouteController.java` + `WebhookDispatcher.java` | **OCP** | MEDIUM | Дублирование regex-паттерна `^[a-zA-Z0-9][a-zA-Z0-9-]*$` (SLUG_PATTERN / PLUGIN_SHORT_ID_PATTERN) — одна и та же валидация в двух местах вместо shared validator |
| 7 | `PermissionIntersectionService.java` | **OCP** | LOW | `IntersectionResult` — внутренний sealed-like класс с 4 static factory methods, но не sealed interface. Не критично, но switch по errorCode в callers не типобезопасен |
| 8 | `McpProxyService.java` | **SRP** | MEDIUM | Содержит `urlOverrides` ConcurrentHashMap для тестов — production-класс загрязнён тестовой инфраструктурой |
| 9 | `McpRouteController.java` | **SRP** | MEDIUM | Делегирующие методы `resolvePluginMcpUrl`, `extractMcpMethod`, `overridePluginUrl` — контроллер дублирует API service-слоя; лишний delegation layer |
| 10 | `SecurityConfig.java` | **SRP** | LOW | 5 методов `disableXxxAutoRegistration()` — шаблонный код для предотвращения дублирования фильтров; можно обобщить |
| 11 | `InstalledPluginCacheService.java` | **SRP** | LOW | 2 перегрузки `isInstalled()` — nullable callback-параметры `Runnable onCacheHit, onCacheMiss` вместо Optional или dedicated metric interface |
| 12 | `PluginAuthFilter.java` | **DIP** | MEDIUM | Создание `ConfigurableJWTProcessor` в `@PostConstruct init()` — JWKS source + JWT processor configuration смешаны с filter logic. JWT processing не выделен в отдельный порт |
| 13 | `PermissionEnforcementFilter.java` | **DIP** | LOW | Внутренне создаёт `new PermissionIntersectionService(properties, permissionCacheService)` — violates DI container, ручное конструирование вместо injection |
| 14 | `InstalledPluginFetchClient.java` | **DIP** | MEDIUM | RestClient wire-up + CB config выполняется внутри конструктора — инфраструктурная сборка смешана с business logic (fetchInstalledStatus). Нет port-интерфейса для fetch-операций |
| 15 | `PermissionFetchClient.java` | **DIP** | MEDIUM | Аналогично InstalledPluginFetchClient — RestClient wire-up + CB config в конструкторе; нет абстракции (port) для permission-fetch operations |
| 16 | `WebhookDispatcher.java` | **SRP** | MEDIUM | Смешивает controller logic (endpoint), retry configuration, async dispatch execution и secret validation в одном классе 179 строк |
| 17 | `PermissionCacheInvalidationListener.java` | **DIP** | LOW | Spring Kafka annotations (`@KafkaListener`, `@Payload`, `@Header`) жёстко привязывают listener к Spring Kafka infrastructure. Event parsing делегирован, но listener contract не отделён port-ом |
| 18 | `GatewayProperties.java` | **ISP** | LOW | Один record-конфиг с 8 nested records (jwt, routes, permissions, permissionCache, installedCache, webhook, bc02, mcp) — потребители зависят от всей конфигурации, хотя каждому нужен 1-2 subsection |

---

## Детали нарушений

---

### 1. [SRP] InstalledPluginFetchClient — 247 строк, превышение лимита

- **Файл:** `client/InstalledPluginFetchClient.java` (247 строк)
- **Проблема:** Класс совмещает 4 обязанности:
  1. RestClient wire-up + timeout configuration (constructor, ~30 строк)
  2. Circuit Breaker configuration (constructor, ~10 строк)
  3. Header propagation (fallback interceptor lambda + `propagateHeader()`, ~20 строк)
  4. Business logic: `fetchInstalledStatus()` + `doFetch()` с JSON parsing (~50 строк)
  
  6 параметров в конструкторе (`RestClient.Builder`, `GatewayProperties`, `CircuitBreakerRegistry`, `ObjectProvider<ServiceTokenPort>`, `ObjectMapper`, `String clientId`) — на грани лимита 7.
- **Рекомендация:**
  1. Вынести RestClient wiring + CB config в `@Configuration` класс (например, `Bc02ClientConfig`), создавая готовый `RestClient` bean
  2. Вынести `propagateHeader()` и fallback interceptor в shared utility (тот же, что и для `PermissionFetchClient`)
  3. Класс-клиент должен содержать только бизнес-метод `fetchInstalledStatus()` + `doFetch()`

---

### 2. [SRP] McpProxyService — 254 строки, превышение лимита

- **Файл:** `routing/McpProxyService.java` (254 строки)
- **Проблема:** Класс совмещает 5 обязанностей:
  1. URL resolution (`resolvePluginMcpUrl()`)
  2. Proxy execution with body streaming (`executeMcpProxy()`)
  3. Header copying (`copyRequestHeaders()`, `copyResponse()`) — дублировано из `ProxyExecutionService`
  4. MCP method extraction (`extractMcpMethod()`, `extractMcpMethodFromRequest()`)
  5. Test URL overrides (`urlOverrides` map + `overridePluginUrl()`)
  
- **Рекомендация:**
  1. Переиспользовать `ProxyExecutionService` для proxy execution вместо дублирования
  2. Вынести `extractMcpMethod()` в utility или dedicated service
  3. Удалить `urlOverrides` — использовать Spring `@TestConfiguration` или `@MockBean` в тестах
  4. Целевой размер: ~100 строк (только MCP-specific URL resolution + delegation)

---

### 3. [SRP] PermissionEnforcementFilter — 208 строк, превышение лимита

- **Файл:** `filter/PermissionEnforcementFilter.java` (208 строк)
- **Проблема:** Фильтр совмещает:
  1. HTTP filter orchestration (extract context, determine path)
  2. Permission intersection logic (делегировано в `PermissionIntersectionService` — хорошо)
  3. Error response writing с detail map construction (3 различных error сценария)
  4. Micrometer metric recording (3 counter-а)
  
  Часть intersection logic уже извлечена (P3-23), но filter всё ещё содержит ~50 строк error formatting.
- **Рекомендация:**
  1. Вынести error formatting для каждого сценария (JWT_MISSING, REVOKED, UNAVAILABLE) в helper methods или error strategy enum
  2. Рассмотреть извлечение metric recording в decorable wrapper

---

### 4. [DRY / OCP] Дублирование proxy-утилит: McpProxyService + ProxyExecutionService

- **Файлы:** `routing/McpProxyService.java`, `routing/ProxyExecutionService.java`
- **Проблема:** Полное посимвольное дублирование:
  - `HOP_BY_HOP_HEADERS` — одинаковый `Set.of(...)` в обоих классах (12 строк)
  - `copyRequestHeaders()` — идентичная реализация (~15 строк)
  - `copyResponse()` — идентичная реализация (~15 строк)
  
  Итого: ~42 строки дублированного кода. При добавлении нового hop-by-hop header нужно менять оба места.
- **Рекомендация:**
  1. Создать `ProxyHeaderUtils` utility class с общими `HOP_BY_HOP_HEADERS`, `copyRequestHeaders()`, `copyResponse()`
  2. Или вынести в существующий `ProxyExecutionService` и переиспользовать из `McpProxyService`

---

### 5. [DRY / OCP] Дублирование между InstalledPluginFetchClient + PermissionFetchClient

- **Файлы:** `client/InstalledPluginFetchClient.java`, `client/PermissionFetchClient.java`
- **Проблема:** Дублировано:
  - `PLUGIN_ID_PATTERN` — одинаковый regex `^[a-zA-Z0-9][a-zA-Z0-9._-]{1,123}[a-zA-Z0-9]$` в обоих классах
  - `propagateHeader()` — идентичный private static метод (5 строк)
  - Fallback header interceptor lambda (~15 строк) — идентичная логика с `propagateHeader` для request-id, correlation-id, user-id, source-service
  - RestClient wiring pattern (timeout config, baseUrl, interceptor setup) — ~30 строк
  
  Итого: ~60 строк дублированного кода.
- **Рекомендация:**
  1. Создать `Bc02ClientConfig` с общим `RestClient.Builder` бином для BC-02 вызовов (timeout, base URL, interceptor)
  2. Вынести `validatePluginId()` + `PLUGIN_ID_PATTERN` в utility (уже статический метод в `PermissionFetchClient`, но лучше в отдельный класс)
  3. Вынести `propagateHeader()` и fallback interceptor в `Bc02HeaderPropagator`

---

### 6. [OCP] Дублирование slug-валидации

- **Файлы:** `routing/McpRouteController.java:37`, `routing/WebhookDispatcher.java:70`
- **Проблема:** Одинаковый regex `^[a-zA-Z0-9][a-zA-Z0-9-]*$` определён дважды:
  - `SLUG_PATTERN` в `McpRouteController`
  - `PLUGIN_SHORT_ID_PATTERN` в `WebhookDispatcher`
  
  Это один и тот же формат идентификатора плагина (slug). При изменении формата нужно менять оба места.
- **Рекомендация:** Создать общий `PluginSlugValidator` с `SLUG_PATTERN` и `isValidSlug()` статическим методом, либо добавить slug validation в существующий utility.

---

### 7. [OCP] IntersectionResult — не типобезопасный sealed type

- **Файл:** `filter/PermissionIntersectionService.java:130-195`
- **Проблема:** `IntersectionResult` реализован как inner class с 4 static factory methods (`granted`, `jwtMissing`, `revoked`, `unavailable`). Callers проверяют `isGranted()` / `isUnavailable()` через boolean flags — нет type-safety.
  
  Если добавится 5-й вариант результата, все callers нужно модифицировать — нарушение OCP.
- **Рекомендация:** Заменить на sealed interface `IntersectionResult` с record-permits:
  ```java
  public sealed interface IntersectionResult {
      record Granted() implements IntersectionResult {}
      record JwtMissing(String requiredPermission) implements IntersectionResult {}
      record Revoked(String pluginId, String requiredPermission) implements IntersectionResult {}
      record Unavailable(String pluginId) implements IntersectionResult {}
  }
  ```
  Callers используют switch pattern matching — добавление нового варианта не ломает существующий код.

---

### 8. [SRP] McpProxyService — тестовая инфраструктура в production коде

- **Файл:** `routing/McpProxyService.java:65-66, 231-240`
- **Проблема:** `ConcurrentHashMap<String, String> urlOverrides` и метод `overridePluginUrl()` существуют исключительно для тестов. Production-класс содержит тестовый state, который:
  - Увеличивает размер класса
  - Создает потенциальный путь для runtime-ошибок (забытый override)
  - Нарушает SRP (production logic + test fixture)
  
- **Рекомендация:**
  1. Удалить `urlOverrides` и `overridePluginUrl()` из `McpProxyService`
  2. В тестах использовать `@MockBean`, `@TestConfiguration` с `@Primary` bean, или WireMock для URL override

---

### 9. [SRP] McpRouteController — избыточный delegation layer

- **Файл:** `routing/McpRouteController.java:159-181`
- **Проблема:** Контроллер содержит 3 метода-делегата:
  - `resolvePluginMcpUrl()` → `mcpProxyService.resolvePluginMcpUrl()`
  - `extractMcpMethod()` → `McpProxyService.extractMcpMethod()`
  - `overridePluginUrl()` → `mcpProxyService.overridePluginUrl()`
  
  Эти методы существуют для тестов (package-private / static access) и не добавляют value. Контроллер должен быть тонким routing layer.
- **Рекомендация:**
  1. Тесты должны напрямую обращаться к `McpProxyService`
  2. Удалить delegating методы из контроллера
  3. Контроллер ограничить: parse request → validate → delegate to service → handle errors

---

### 10. [SRP] SecurityConfig — шаблонный код auto-registration disabling

- **Файл:** `config/SecurityConfig.java:94-140`
- **Проблема:** 5 идентичных методов `disableXxxAutoRegistration()` для каждого фильтра. Каждый метод создаёт `FilterRegistrationBean` и disables его — одинаковый шаблон, разные типы.
  
  При добавлении нового фильтра нужно добавить ещё один метод — нарушение OCP.
- **Рекомендация:** Создать generic helper-метод:
  ```java
  private <T extends OncePerRequestFilter> FilterRegistrationBean<T> disableAutoRegistration(T filter) {
      var registration = new FilterRegistrationBean<>(filter);
      registration.setEnabled(false);
      return registration;
  }
  ```
  Или использовать `FilterRegistrationBean` bean definition в каждом filter классе через `@Bean`.

---

### 11. [SRP] InstalledPluginCacheService — nullable callback parameters

- **Файл:** `cache/InstalledPluginCacheService.java:57-82`
- **Проблема:** Метод `isInstalled()` имеет overload с nullable `Runnable` callbacks:
  ```java
  public Optional<Boolean> isInstalled(
      String pluginId, String tenantId, Runnable onCacheHit, Runnable onCacheMiss)
  ```
  Null-checking callbacks внутри business logic (`if (onCacheHit != null) onCacheHit.run()`) — смешивает metric recording с cache logic.
  
- **Рекомендация:**
  1. Использовать `MeterRegistry` напрямую внутри cache service вместо внешних callbacks
  2. Или передавать `Optional<Runnable>` / NOOP sentinel вместо nullable

---

### 12. [DIP] PluginAuthFilter — JWT processor configuration в filter

- **Файл:** `filter/PluginAuthFilter.java:63-90`
- **Проблема:** Метод `@PostConstruct init()` создаёт `ConfigurableJWTProcessor` с:
  - `JWKSource` creation (JWKS URL → HTTP fetch)
  - `JWSKeySelector` configuration (RS256)
  - `DefaultJWTClaimsVerifier` with issuer/audience
  - Type verifier configuration
  
  Это инфраструктурная сборка (JWKS HTTP client, JWT validation pipeline), смешанная с filter orchestration. JWKS source creation — внешняя HTTP-зависимость, не абстрагированная port-ом.
- **Рекомендация:**
  1. Вынести JWT processor creation в `JwtProcessorConfig` `@Configuration` класс
  2. Инжектировать `ConfigurableJWTProcessor<SecurityContext>` как bean
  3. Filter должен содержать только: extract token → process → set context

---

### 13. [DIP] PermissionEnforcementFilter — ручное конструирование service

- **Файл:** `filter/PermissionEnforcementFilter.java:58-59`
- **Проблема:** В конструкторе filter создаётся `new PermissionIntersectionService(properties, permissionCacheService)` вместо injection через Spring:
  ```java
  this.intersectionService = new PermissionIntersectionService(properties, permissionCacheService);
  ```
  Это нарушает DIP — filter зависит от конкретного класса, а не от абстракции. Также prevents mock injection в тестах.
- **Рекомендация:** Инжектировать `PermissionIntersectionService` напрямую:
  ```java
  public PermissionEnforcementFilter(
      PermissionIntersectionService intersectionService,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) { ... }
  ```

---

### 14. [DIP] InstalledPluginFetchClient — нет port-интерфейса

- **Файл:** `client/InstalledPluginFetchClient.java`
- **Проблема:** Класс является concrete `@Component` без port-интерфейса. Consumers (`InstalledPluginCacheService`) напрямую зависят от конкретного класса. RestClient wire-up и CB config выполняются внутри конструктора — нет разделения между "что делает клиент" и "как он устроен".
  
  Аналогичная проблема в `PermissionFetchClient`.
- **Рекомендация:**
  1. Создать port-интерфейс `PluginInstalledCheckPort` с методом `Optional<Boolean> fetchInstalledStatus(String, String)`
  2. Класс реализует интерфейс
  3. RestClient wiring вынести в configuration

---

### 15. [DIP] PermissionFetchClient — нет port-интерфейса

- **Файл:** `client/PermissionFetchClient.java`
- **Проблема:** Аналогично #14: concrete `@Component` без port-интерфейса. Consumers (`PermissionCacheService`) зависят от конкретного класса.
  
  RestClient wire-up + CB config + fallback header interceptor — всё в конструкторе (~50 строк инфраструктурного кода).
- **Рекомендация:**
  1. Создать port-интерфейс `PluginPermissionFetchPort` с методом `Optional<List<String>> fetchPermissions(String)`
  2. Вынести shared BC-02 RestClient wiring в `Bc02ClientConfig`

---

### 16. [SRP] WebhookDispatcher — смешивает controller, retry config и dispatch

- **Файл:** `routing/WebhookDispatcher.java` (179 строк)
- **Проблема:** Класс совмещает:
  1. REST controller endpoint (`dispatchWebhook()` — `@PostMapping`)
  2. Retry configuration (constructor, `RetryConfig` + `RetryRegistry`)
  3. Async dispatch execution (`CompletableFuture.runAsync()`)
  4. Secret validation (MessageDigest.isEqual timing-safe comparison)
  5. Pod endpoint resolution (`resolvePluginPodEndpoint()`)
  
  Это controller + service + config в одном классе.
- **Рекомендация:**
  1. Разделить на `WebhookController` (endpoint + validation) и `WebhookDispatchService` (async execution + retry)
  2. Retry config вынести в `WebhookConfig` или использовать bean из `ResilienceConfig`
  3. Secret validation — в dedicated validator или gateway filter

---

### 17. [DIP] PermissionCacheInvalidationListener — прямая зависимость от Spring Kafka

- **Файл:** `event/PermissionCacheInvalidationListener.java`
- **Проблема:** Класс напрямую зависит от Spring Kafka infrastructure:
  - `@KafkaListener` annotation
  - `@Payload`, `@Header` parameter annotations
  - `org.springframework.kafka.annotation.KafkaListener`
  - `org.springframework.messaging.handler.annotation.*`
  
  Event parsing уже хорошо делегирован в `PermissionRevocationEventParser`, но listener contract не отделён port-интерфейсом от Spring Kafka.
  
  *Примечание:* Это LOW severity — для Kafka listeners это стандартный Spring паттерн. Но если в будущем появится необходимость в non-Kafka event source (например, polling), придётся переписывать listener.
- **Рекомендация:** Рассмотреть выделение `PermissionRevocationHandler` port-интерфейса:
  ```java
  public interface PermissionRevocationHandler {
      void handleRevocation(String message, String correlationId, String requestId);
  }
  ```
  Spring Kafka listener становится adapter-ом, реализующим этот интерфейс.

---

### 18. [ISP] GatewayProperties — один конфиг для всех consumers

- **Файл:** `config/GatewayProperties.java`
- **Проблема:** `GatewayProperties` — один record с 8 subsections: `jwt`, `routes`, `permissions`, `permissionCache`, `installedCache`, `webhook`, `bc02`, `mcp`.
  
  Каждый consumer зависит от всей конфигурации, хотя использует 1-2 subsection:
  - `PluginAuthFilter` — нужен только `jwt()`
  - `WebhookDispatcher` — нужен только `webhook()`
  - `McpProxyService` — нужен только `mcp()`
  - `RouteResolutionService` — нужен только `routes()`
  - `PermissionCacheService` — нужен только `permissionCache()`
  - `InstalledPluginCacheService` — нужен только `installedCache()`
  
  Изменение webhook-конфигурации вызывает recompilation/redeploy всех зависимых классов.
- **Рекомендация:** Это LOW severity — record-based config в Spring Boot convention. Для улучшения:
  1. Каждый consumer может деструктурировать только нужные subsection
  2. Или создать отдельные `@ConfigurationProperties` records для каждого concern (JwtProperties, WebhookProperties, McpProperties)
  3. Текущий подход приемлем для gateway-сервиса с единым config namespace

---

## Статистика по принципам

| Принцип | Количество нарушений | HIGH | MEDIUM | LOW |
|---------|---------------------|------|--------|-----|
| **S (SRP)** | 8 | 2 | 4 | 2 |
| **O (OCP)** | 4 | 2 | 1 | 1 |
| **L (LSP)** | 0 | 0 | 0 | 0 |
| **I (ISP)** | 1 | 0 | 0 | 1 |
| **D (DIP)** | 5 | 0 | 3 | 2 |
| **Итого** | **18** | **4** | **8** | **6** |

---

## Положительные аспекты (compliance)

1. **LSP — полное соответствие.** Ни один adapter/subtype не бросает `UnsupportedOperationException`. Все fallback-сценарии используют `Optional.empty()` с graceful degradation.
2. **Хорошее разделение cache/event logic.** `PermissionRevocationEventParser` корректно извлечён из `PermissionCacheService`.
3. **Intersection logic extracted.** `PermissionIntersectionService` выделен из `PermissionEnforcementFilter` (P3-23).
4. **Route resolution extracted.** `RouteResolutionService` и `ProxyExecutionService` выделены из `PluginRouteResolver` (P3-22).
5. **MCP proxy extracted.** `McpProxyService` выделен из `McpRouteController` (P3-21).
6. **Fail-closed pattern.** Все проверки (permissions, installed) корректно fail-closed при недоступности BC-02 — return `Optional.empty()` или 503.
7. **DTO immutability.** Все DTO — Java records с defensive copies.
8. **Нет if-else на type strings.** Route resolution использует Map lookup, а не switch/case на строковых типах.

---

## Рекомендуемые приоритеты исправления

### Priority 1 (HIGH) — устранение дублирования

| # | Что | Затраты | Файлы |
|---|-----|---------|-------|
| 4 | Вынести `HOP_BY_HOP_HEADERS`, `copyRequestHeaders()`, `copyResponse()` в общий utility | ~1h | `McpProxyService`, `ProxyExecutionService`, новый `ProxyHeaderUtils` |
| 5 | Вынести BC-02 RestClient wiring, `PLUGIN_ID_PATTERN`, `propagateHeader()` в shared config | ~2h | `InstalledPluginFetchClient`, `PermissionFetchClient`, новый `Bc02ClientConfig` |

### Priority 2 (MEDIUM) — SRP violations >200 строк

| # | Что | Затраты | Файлы |
|---|-----|---------|-------|
| 1 | Рефакторинг `InstalledPluginFetchClient` — вынести wiring в config | ~1h | `InstalledPluginFetchClient` |
| 2 | Рефакторинг `McpProxyService` — переиспользовать `ProxyExecutionService` | ~2h | `McpProxyService` |
| 3 | Рефакторинг `PermissionEnforcementFilter` — вынести error formatting | ~1h | `PermissionEnforcementFilter` |
| 16 | Разделить `WebhookDispatcher` на controller + service | ~1.5h | `WebhookDispatcher` |

### Priority 3 (LOW) — DIP / ISP improvements

| # | Что | Затраты | Файлы |
|---|-----|---------|-------|
| 13 | Заменить `new PermissionIntersectionService(...)` на injection | ~15min | `PermissionEnforcementFilter` |
| 12 | Вынести JWT processor config из `PluginAuthFilter` | ~30min | `PluginAuthFilter` |
| 14-15 | Добавить port-интерфейсы для fetch clients | ~1h | `InstalledPluginFetchClient`, `PermissionFetchClient` |
| 7 | Заменить `IntersectionResult` на sealed interface | ~1h | `PermissionIntersectionService` + callers |
