# GRASP-аудит микросервиса `adapstory-plugin-gateway`

> **Дата аудита:** 2025-07  
> **Аудитор:** AI-аудитор GRASP-паттернов  
> **Объём:** 33 production-класса (src/main/java), 24 тест-класса  
> **Архитектурный стиль:** Spring Boot REST-gateway, Redis cache-aside, Kafka consumer, JWT-auth, circuit breaker

---

## Сводная оценка

| # | GRASP-паттерн               | Оценка | Вердикт      |
|---|-----------------------------|--------|--------------|
| 1 | Information Expert          | 8/10   | ✅ Хороший   |
| 2 | Controller                  | 7/10   | ✅ Хороший   |
| 3 | Creator                     | 9/10   | ✅ Отличный  |
| 4 | Low Coupling                | 6/10   | ⚠️ Приемлемый|
| 5 | High Cohesion               | 7/10   | ✅ Хороший   |
| 6 | Polymorphism                | 5/10   | ⚠️ Приемлемый|
| 7 | Pure Fabrication            | 9/10   | ✅ Отличный  |
| 8 | Indirection                 | 7/10   | ✅ Хороший   |
| 9 | Protected Variations        | 8/10   | ✅ Хороший   |

**Общая оценка: 7.3 / 10** — архитектура в целом следует GRASP-принципам. Основные риски — отсутствие интерфейсных абстракций (Polymorphism) и дублирование конфигурации circuit breaker в клиентах (Low Coupling / High Cohesion).

---

## Каталог классов по пакетам

| Пакет         | Классы                                                                                      | Слой              |
|---------------|---------------------------------------------------------------------------------------------|-------------------|
| `config/`     | `AsyncConfig`, `GatewayProperties`, `JwksHealthIndicator`, `ResilienceConfig`, `SecurityConfig` | Конфигурация      |
| `dto/`        | `GatewayErrorResponse`, `PluginInstalledResponse`, `PluginPermissionsResponse`, `PluginSecurityContext` | Data Transfer     |
| `cache/`      | `InstalledPluginCacheService`, `PermissionCacheService`, `PermissionRevocationEventParser`     | Кеширование       |
| `client/`     | `InstalledPluginFetchClient`, `PermissionFetchClient`                                        | REST-клиенты      |
| `filter/`     | `PluginAuthFilter`, `PluginAuthenticationToken`, `PluginInstalledCheckFilter`, `PermissionEnforcementFilter`, `PermissionIntersectionService`, `HeaderInjectionFilter`, `PluginMcpJwtClaimFilter` | Фильтры запросов  |
| `routing/`    | `McpRouteController`, `McpProxyService`, `PluginRouteResolver`, `ProxyExecutionService`, `RouteResolutionService`, `WebhookDispatcher` | Маршрутизация     |
| `event/`      | `PermissionCacheInvalidationListener`                                                        | Kafka consumer    |
| `util/`       | `FetchClientUtils`, `GatewayErrorWriter`, `PluginSlugValidator`, `ProxyHeaderUtils`          | Утилиты           |
| root          | `PluginGatewayApplication`                                                                  | Точка входа       |

---

## 1. Information Expert

> **Принцип:** Ответственность назначается классу, который обладает информацией, необходимой для её выполнения.

### ✅ Соблюдается

| Класс | Обоснование |
|-------|-------------|
| `PluginSecurityContext` | record, содержит `pluginId`, `tenantId`, `permissions`, `trustLevel` — эксперт по данным контекста безопасности плагина. Все потребители читают информацию из него, а не из JWT-claims напрямую. |
| `PermissionIntersectionService.IntersectionResult` | Инкапсулирует результат пересечения разрешений (`granted`/`jwtMissing`/`revoked`/`unavailable`) с кодами ошибок. Вызывающий код не вычисляет эти данные повторно. |
| `PermissionRevocationEventParser` | Эксперт по разбору CloudEvents `PluginPermissionsRevoked`: парсинг JSON, извлечение `ce-id`, валидация payload, извлечение `pluginId` с fallback на `snake_case`. |
| `InstalledPluginCacheService` | Эксперт по кешу установки плагинов: строит ключи, управляет TTL, negative cache sentinel, знает fallback-стратегию при miss. |
| `PermissionCacheService` | Эксперт по кешу разрешений: хранение, чтение, инвалидация, negative caching. |
| `GatewayProperties` | Единый Information Expert по конфигурации gateway: JWT, routes, permissions, cache, webhook, MCP — все nested records. |
| `RouteResolutionService` | Эксперт по извлечению route key из path и разрешению target BC URL. |

### ⚠️ Нарушения и замечания

**Нарушение IE-1: `PermissionFetchClient.validatePluginId()` — чужая ответственность**

`PermissionRevocationEventParser.extractPluginIdFromData()` вызывает статический метод `PermissionFetchClient.validatePluginId(value)`:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/cache/PermissionRevocationEventParser.java#L103-108
    String value = pluginIdNode.asText();
    try {
      PermissionFetchClient.validatePluginId(value);
    } catch (IllegalArgumentException | NullPointerException e) {
```

**Проблема:** Класс из слоя `cache/` зависит от класса из слоя `client/` ради валидации. Валидация `pluginId` — это не ответственность REST-клиента. `FetchClientUtils` уже содержит `PLUGIN_ID_PATTERN`, но метод `validatePluginId()` остался в `PermissionFetchClient`.

**Рекомендация:** Перенести `validatePluginId()` в `FetchClientUtils`, где уже живёт `PLUGIN_ID_PATTERN`.

---

**Замечание IE-2: `PluginAuthFilter` — слишком много знаний о JWT-структуре**

Фильтр вручную извлекает конкретные claim-ключи (`"plugin_id"`, `"adapstory_tenant_id"`, `"permissions"`, `"trust_level"`):

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginAuthFilter.java#L103-112
      String pluginId = claims.getStringClaim("plugin_id");
      String tenantId = claims.getStringClaim("adapstory_tenant_id");
      List<String> permissions = claims.getStringListClaim("permissions");
      String trustLevel = claims.getStringClaim("trust_level");
```

Если структура JWT изменится (например, `permissions` станет вложенным объектом), придётся менять `PluginAuthFilter`. Более чистый подход — выделить `JwtClaimsExtractor` (Pure Fabrication), который был бы экспертом по маппингу JWT claims → `PluginSecurityContext`.

**Рекомендация:** Вынести маппинг JWT claims → DTO в отдельный класс `PluginJwtClaimsMapper`.

---

## 2. Controller

> **Принцип:** Первый объект за UI-слоем, который принимает и координирует системные операции.

### ✅ Соблюдается

| Класс | Обоснование |
|-------|-------------|
| `McpRouteController` | Чистый контроллер MCP-маршрутизации: валидация slug → делегирование `McpProxyService` → обработка ошибок через `GatewayErrorWriter`. Не содержит бизнес-логики. |
| `PluginRouteResolver` | REST-контроллер gateway-прокси: принимает `/api/bc-02/gateway/v1/api/**`, делегирует resolution → `RouteResolutionService`, execution → `ProxyExecutionService`, error-handling → `GatewayErrorWriter`. |
| `WebhookDispatcher` | REST-контроллер вебхуков: `POST /{pluginShortId}`, валидация, секрет, асинхронный dispatch. |
| `SecurityConfig` | Координатор фильтр-цепочки: определяет порядок фильтров, публичные эндпоинты, SecurityFilterChain-бины. |
| `PermissionCacheInvalidationListener` | Координатор Kafka-события: принимает сообщение → парсинг (делегат) → idempotency (делегат) → инвалидация кеша (делегат) → метрика. |

### ⚠️ Нарушения и замечания

**Нарушение C-1: `PluginRouteResolver` — нестандартное именование**

Класс называется `PluginRouteResolver`, но аннотирован `@RestController` и обрабатывает HTTP-запросы. Это вводит в заблуждение — по имени ожидается сервис разрешения маршрутов, а не контроллер.

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/routing/PluginRouteResolver.java#L36-37
@PermitAll
@RestController
```

**Рекомендация:** Переименовать в `GatewayProxyController` или `PluginGatewayController`. `RouteResolutionService` уже выделена как сервис.

---

**Нарушение C-2: `WebhookDispatcher` — контроллер с бизнес-логикой**

`WebhookDispatcher` совмещает роль REST-контроллера с retry-конфигурацией, валидацией секрета, resolution endpoint-а и async dispatch. Это нарушает как Controller (слишком много ответственности), так и High Cohesion.

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/routing/WebhookDispatcher.java#L49-65
  public WebhookDispatcher(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      @Qualifier("webhookExecutor") Executor webhookExecutor) {
    ...
    RetryConfig retryConfig = RetryConfig.custom()
        .maxAttempts(cfg.retryMaxAttempts())
```

**Рекомендация:** Разделить на `WebhookController` (REST endpoint + валидация) и `WebhookDispatchService` (retry, async dispatch, endpoint resolution).

---

## 3. Creator

> **Принцип:** Класс B должен создавать объект A, если B содержит A, B записывает A, B тесно использует A, или B имеет данные для инициализации A.

### ✅ Соблюдается

| Создатель               | Создаваемый объект                 | Обоснование (Creator rule)                   |
|-------------------------|------------------------------------|----------------------------------------------|
| `PluginAuthFilter`      | `PluginSecurityContext`, `PluginAuthenticationToken` | Фильтр валидирует JWT и обладает всеми claim-данными для создания контекста и токена. |
| `PermissionIntersectionService` | `IntersectionResult`      | Сервис вычисляет результат пересечения — он единственный обладает данными для создания `IntersectionResult`. |
| `GatewayErrorWriter`    | `GatewayErrorResponse`             | Утилита формирует ответ с ошибкой — владеет всеми параметрами (status, error, message, path, requestId). |
| `PluginPermissionsResponse.Data` | defensive copy `List.copyOf(permissions)` | Record сам обеспечивает иммутабельность — корректное создание. |
| `InstalledPluginCacheService` / `PermissionCacheService` | кеш-записи в Redis | Кеш-сервисы знают формат ключа и TTL — они создают записи. |
| `McpRouteController`    | делегирует создание URL в `McpProxyService` | Контроллер не создаёт URL сам — делегирует эксперту. |

### ⚠️ Нарушения

Значительных нарушений паттерна Creator не обнаружено. Создание объектов распределено корректно.

---

## 4. Low Coupling

> **Принцип:** Минимизировать зависимости между классами для уменьшения влияния изменений.

### ✅ Соблюдается

| Аспект | Пример |
|--------|--------|
| Статические утилиты без состояния | `GatewayErrorWriter`, `ProxyHeaderUtils`, `PluginSlugValidator`, `FetchClientUtils` — 0 зависимостей от Spring-бинов |
| Record DTO без поведения | `PluginSecurityContext`, `GatewayErrorResponse`, `PluginPermissionsResponse`, `PluginInstalledResponse` — нет Spring-зависимостей |
| Constructor injection | Все классы используют constructor injection (не field injection) |
| Выделение сервисов | `RouteResolutionService`, `ProxyExecutionService`, `PermissionIntersectionService`, `McpProxyService` — уменьшают coupling между слоями |
| Конфигурация через record | `GatewayProperties` — единая точка конфигурации |

### ⚠️ Нарушения

**Нарушение LC-1: Дублирование circuit breaker конфигурации**

Оба клиента (`InstalledPluginFetchClient` и `PermissionFetchClient`) содержат идентичный код конфигурации circuit breaker:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/client/InstalledPluginFetchClient.java#L82-89
    this.circuitBreaker =
        circuitBreakerRegistry.circuitBreaker(
            CB_NAME,
            CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(10))
                .permittedNumberOfCallsInHalfOpenState(3)
                .slowCallDurationThreshold(Duration.ofSeconds(5))
                .minimumNumberOfCalls(5)
                .build());
```

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/client/PermissionFetchClient.java#L72-80
    this.circuitBreaker =
        circuitBreakerRegistry.circuitBreaker(
            CB_NAME,
            CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .failureRateThreshold(50)
                ...
```

**Проблема:** При изменении параметров CB нужно менять оба класса. `ResilienceConfig` создаёт default config, но оба клиента его переопределяют собственными кастомными конфигурациями с одинаковыми значениями.

**Рекомендация:** Использовать default config из `ResilienceConfig` или вынести фабричный метод в `FetchClientUtils`.

---

**Нарушение LC-2: Дублирование RestClient-конфигурации**

Оба клиента (`InstalledPluginFetchClient`, `PermissionFetchClient`) содержат одинаковый код для:
- Timeout configuration (`CONNECT_TIMEOUT_MS = 3000`, `READ_TIMEOUT_MS = 3000`)
- `ServiceTokenPort` injection с fallback
- Header interceptor setup

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/client/InstalledPluginFetchClient.java#L66-77
    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));

    RestClient.Builder builder =
        restClientBuilder.baseUrl(properties.bc02().baseUrl()).requestFactory(factory);
    ServiceTokenPort tokenPort = serviceTokenPort.getIfAvailable();
    if (tokenPort != null) {
      builder.requestInterceptor(
          new ServiceHeaderInterceptor(
              tokenPort, TARGET_AUDIENCE, FetchClientUtils.HEADER_SOURCE_SERVICE, clientId));
    } else {
      builder.requestInterceptor(FetchClientUtils.fallbackHeaderInterceptor());
    }
```

**Рекомендация:** Вынести общую конфигурацию `RestClient` в factory-метод в `FetchClientUtils` или `Bc02ClientConfig`.

---

**Нарушение LC-3: Кросс-слойная зависимость `cache/` → `client/`**

`PermissionRevocationEventParser` (слой `cache/`) импортирует `PermissionFetchClient` (слой `client/`) для валидации `pluginId`. Это создаёт зависимость слоя кеширования от слоя REST-клиентов.

```
cache/PermissionRevocationEventParser → client/PermissionFetchClient.validatePluginId()
```

**Рекомендация:** Перенести валидацию в общий `util/FetchClientUtils`.

---

**Нарушение LC-4: Фильтры зависят от `ObjectMapper` напрямую**

Четыре фильтра (`PluginAuthFilter`, `PluginInstalledCheckFilter`, `PermissionEnforcementFilter`, `PluginMcpJwtClaimFilter`) и два контроллера (`McpRouteController`, `PluginRouteResolver`) напрямую зависят от `ObjectMapper` и делегируют `GatewayErrorWriter`. Это создаёт coupling к Jackson.

**Рекомендация:** Инжектировать `GatewayErrorWriter` как компонент (spring bean) вместо передачи `ObjectMapper` через конструктор.

---

## 5. High Cohesion

> **Принцип:** Класс должен иметь одну чётко определенную ответственность; все его методы должны быть связаны с ней.

### ✅ Соблюдается

| Класс | Единственная ответственность |
|-------|------------------------------|
| `InstalledPluginCacheService` | Cache-aside для проверки установки плагинов в Redis |
| `PermissionCacheService` | Cache-aside для разрешений плагинов в Redis |
| `PermissionRevocationEventParser` | Парсинг и валидация CloudEvents `PluginPermissionsRevoked` |
| `RouteResolutionService` | Разрешение route key → target URL |
| `ProxyExecutionService` | Исполнение HTTP-проксирования с body streaming |
| `McpProxyService` | Проксирование MCP JSON-RPC к plugin backend |
| `PermissionIntersectionService` | Вычисление пересечения JWT × manifest permissions |
| `GatewayErrorWriter` | Формирование стандартизированного JSON-ответа с ошибкой |
| `PluginSlugValidator` | Валидация формата slug |
| `ProxyHeaderUtils` | Копирование safe-заголовков между proxy legs |
| `FetchClientUtils` | Общие утилиты для REST-клиентов BC-02 |
| `PluginAuthenticationToken` | Представление authentication token в Spring Security |
| `GatewayProperties` | Конфигурация (nested records по доменам) |

### ⚠️ Нарушения

**Нарушение HC-1: `PluginAuthFilter` — 4 ответственности в одном классе**

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginAuthFilter.java#L35-50
public class PluginAuthFilter extends OncePerRequestFilter {
  // 1. Инициализация JWT processor (@PostConstruct init())
  // 2. Валидация JWT
  // 3. Извлечение claims → PluginSecurityContext
  // 4. Установка Spring Security Authentication
```

Фильтр совмещает:
1. **Конфигурацию JWKS/JWT processor** (`init()` — 20 строк)
2. **Валидацию JWT токена**
3. **Маппинг claims → DTO** (извлечение 4 claim-ключей)
4. **Управление SecurityContext** (set authentication, clear in finally)

**Рекомендация:** Вынести `init()` JWT processor конфигурацию в отдельный `@Configuration`-бин или `JwtProcessorFactory`. Вынести маппинг claims в `PluginJwtClaimsMapper`.

---

**Нарушение HC-2: `WebhookDispatcher` — 5 ответственностей**

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/routing/WebhookDispatcher.java#L39-65
public class WebhookDispatcher {
  // 1. REST endpoint (@PostMapping)
  // 2. Retry configuration (RetryConfig)
  // 3. Secret validation (MessageDigest.isEqual)
  // 4. Endpoint resolution (resolvePluginPodEndpoint)
  // 5. Async dispatch (CompletableFuture.runAsync + executeWithRetry)
```

**Рекомендация:** Разделить:
- `WebhookController` — REST endpoint, валидация
- `WebhookDispatchService` — retry, async dispatch, endpoint resolution

---

**Нарушение HC-3: `InstalledPluginFetchClient` — конфигурация + операция**

Клиент совмещает:
1. Создание `RestClient` с interceptor-ами (конфигурация)
2. Создание `CircuitBreaker` (конфигурация)
3. Выполнение HTTP-запроса и парсинг ответа (операция)

Конструктор содержит ~40 строк инфраструктурного кода. Тестовый конструктор `InstalledPluginFetchClient(RestClient, CircuitBreaker, ObjectMapper)` подтверждает, что тестам не нужна конфигурационная логика.

**Рекомендация:** Вынести создание `RestClient` и `CircuitBreaker` в `@Configuration`-класс (например, `Bc02ClientConfig`).

---

## 6. Polymorphism

> **Принцип:** Использовать полиморфные операции для обработки альтернативных вариантов поведения на основе типа.

### ✅ Соблюдается

| Пример | Обоснование |
|--------|-------------|
| `PluginAuthenticationToken extends AbstractAuthenticationToken` | Корректное использование polymorphism для Spring Security integration. Переопределены `getCredentials()`, `getPrincipal()`. |
| `OncePerRequestFilter` (5 фильтров) | Все фильтры наследуют `OncePerRequestFilter` и реализуют `doFilterInternal()` — полиморфная фильтр-цепочка. |
| `JwksHealthIndicator implements HealthIndicator` | Полиморфная реализация health check через Spring Boot actuator interface. |
| Circuit Breaker pattern | Поведенческий polymorphism: CB переключается между CLOSED → OPEN → HALF_OPEN, изменяя поведение `executeSupplier()`. |
| Record `GatewayProperties` с nested records | Полиморфизм через композицию — разные config-секции как вложенные типы. |

### ⚠️ Нарушения

**Нарушение P-1: Отсутствие интерфейсов для сервисов кеширования**

`InstalledPluginCacheService` и `PermissionCacheService` — конкретные классы без интерфейсов. Фильтры (`PluginInstalledCheckFilter`, `PermissionIntersectionService`) зависят от конкретных реализаций:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginInstalledCheckFilter.java#L47
  private final InstalledPluginCacheService cacheService;
```

При необходимости заменить Redis на другой cache backend (например, Caffeine для local-cache) придётся менять типы в конструкторах всех потребителей.

**Рекомендация:** Ввести интерфейсы:
- `InstalledPluginCachePort` с методом `isInstalled()`
- `PermissionCachePort` с методами `getCachedPermissions()`, `fetchAndCachePermissions()`, `invalidate()`

---

**Нарушение P-2: Отсутствие интерфейсов для REST-клиентов**

`InstalledPluginFetchClient` и `PermissionFetchClient` — конкретные классы без интерфейсов. Тесты используют reflection/constructor injection для подмены, а не polymorphism.

**Рекомендация:** Ввести:
- `InstalledPluginFetchPort` с методом `fetchInstalledStatus()`
- `PermissionFetchPort` с методом `fetchPermissions()`

---

**Нарушение P-3: `IntersectionResult` — Boolean flags вместо type hierarchy**

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PermissionIntersectionService.java#L122-163
  public static final class IntersectionResult {
    private final boolean granted;
    private final boolean unavailable;
    private final String errorCode;
```

Результат представлен одним классом с boolean-флагами вместо полиморфной иерархии. Это приводит к проверкам вида `if (result.isUnavailable())` / `if (!result.isGranted())` в вызывающем коде — типичный anti-pattern "tagged union без union".

**Рекомендация:** Использовать sealed interface (Java 17+):

```java
public sealed interface IntersectionResult {
    record Granted() implements IntersectionResult {}
    record JwtMissing(String requiredPermission) implements IntersectionResult {}
    record Revoked(String pluginId, String requiredPermission) implements IntersectionResult {}
    record Unavailable(String pluginId) implements IntersectionResult {}
}
```

---

## 7. Pure Fabrication

> **Принцип:** Создание искусственного класса, не представляющего концепцию домена, для улучшения cohesion/coupling.

### ✅ Соблюдается отлично

| Pure Fabrication              | Выделен из                            | Обоснование выделения |
|-------------------------------|---------------------------------------|-----------------------|
| `GatewayErrorWriter`          | Все фильтры и контроллеры             | Централизует формат Pattern 8 ошибок. Статический, без Spring-зависимостей. |
| `FetchClientUtils`            | `InstalledPluginFetchClient` + `PermissionFetchClient` | Общие `PLUGIN_ID_PATTERN`, `propagateHeader()`, `fallbackHeaderInterceptor()`. |
| `ProxyHeaderUtils`            | `McpProxyService` + `ProxyExecutionService` | Hop-by-hop header filtering, safe copy request/response headers. |
| `PluginSlugValidator`         | `McpRouteController` + `WebhookDispatcher` | Единый regex для slug-валидации. |
| `PermissionIntersectionService` | `PermissionEnforcementFilter`       | Выделена логика пересечения JWT × manifest permissions (P3-23). |
| `PermissionRevocationEventParser` | `PermissionCacheService` + `PermissionCacheInvalidationListener` | Выделен парсинг CloudEvents из кеш-сервиса. |
| `RouteResolutionService`     | `PluginRouteResolver`                 | Выделена маршрутизация из контроллера (P3-22). |
| `ProxyExecutionService`       | `PluginRouteResolver`                 | Выделено исполнение прокси (P3-22). |
| `McpProxyService`             | `McpRouteController`                  | Выделено MCP-проксирование (P3-21). |
| `ResilienceConfig`            | Рассредоточена в клиентах            | Централизованная конфигурация circuit breaker registry. |
| `AsyncConfig`                 | `WebhookDispatcher`                   | Конфигурация managed executor для webhook dispatch. |

### ⚠️ Недостатки

**Замечание PF-1: Отсутствует `Bc02ClientConfig`**

Общий код конфигурации `RestClient` для BC-02 (timeout, service token interceptor, circuit breaker) дублирован в двух клиентах. Это кандидат на Pure Fabrication.

**Рекомендация:** Создать `Bc02ClientConfig`:
```java
@Configuration
class Bc02ClientConfig {
    @Bean("bc02RestClient")
    RestClient bc02RestClient(RestClient.Builder builder, GatewayProperties props, ...) { ... }
}
```

---

**Замечание PF-2: Отсутствует `PluginJwtClaimsMapper`**

Маппинг JWT claims → `PluginSecurityContext` (строковые ключи `"plugin_id"`, `"adapstory_tenant_id"`, etc.) — чистая fabrication, которая позволила бы `PluginAuthFilter` не знать о структуре JWT.

---

## 8. Indirection

> **Принцип:** Промежуточный объект中介ует между компонентами для их развязки.

### ✅ Соблюдается

| Посредник                     | Что разделяет                                |
|-------------------------------|----------------------------------------------|
| `GatewayProperties`           | Код от конкретных YAML-ключей и default-значений |
| `PermissionCacheService`      | Фильтры от прямых обращений к Redis и BC-02 REST |
| `InstalledPluginCacheService` | Фильтры от прямых обращений к Redis и BC-02 REST |
| `RouteResolutionService`      | Контроллер от конфигурации маршрутов (`routes` map) |
| `CircuitBreakerRegistry`      | Клиенты от прямого управления состоянием CB |
| `PermissionIntersectionService` | `PermissionEnforcementFilter` от прямых обращений к кешу |
| `McpProxyService`             | `McpRouteController` от RestClient и endpoint resolution |
| `FetchClientUtils.fallbackHeaderInterceptor()` | Клиенты от знания деталей header propagation при отсутствии `ServiceTokenPort` |
| `SecurityConfig`              | Фильтры от порядка регистрации в servlet container |

### ⚠️ Нарушения

**Нарушение I-1: Фильтры напрямую зависят от `ObjectMapper`**

Четыре фильтра и два контроллера инжектируют `ObjectMapper` и передают его в `GatewayErrorWriter`:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginAuthFilter.java#L44
  private final ObjectMapper objectMapper;
```

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginAuthFilter.java#L127-130
  private void writeError(...) throws IOException {
    GatewayErrorWriter.writeError(objectMapper, response, request, status, error, message, details);
  }
```

Это создаёт coupling между фильтрами и Jackson. Если формат сериализации изменится, все фильтры будут затронуты (хотя `GatewayErrorWriter` централизует логику, `ObjectMapper` всё равно пробрасывается через конструкторы).

**Рекомендация:** Обернуть `GatewayErrorWriter` + `ObjectMapper` в Spring-bean `GatewayErrorResponseWriter` и инжектировать один бин вместо `ObjectMapper` + static util.

---

**Нарушение I-2: Отсутствует indirection для Micrometer counters**

`PluginInstalledCheckFilter` создаёт и регистрирует собственные Micrometer counters:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginInstalledCheckFilter.java#L63-76
    this.notInstalledCounter =
        Counter.builder("plugin_gateway_not_installed_total")
            .description("...")
            .register(meterRegistry);
    this.unavailableCounter =
        Counter.builder("plugin_gateway_installed_unavailable_total")
            ...
    this.cacheHitCounter =
        Counter.builder("plugin_gateway_installed_cache_hit_total")
            ...
    this.cacheMissCounter =
        Counter.builder("plugin_gateway_installed_cache_miss_total")
            ...
```

Фильтр знает имена метрик, их описания и логику регистрации. Аналогично `PermissionEnforcementFilter` инкрементит counters напрямую через `meterRegistry.counter(...)`.

**Рекомендация:** Вынести metric tracking в `GatewayMetrics` (Pure Fabrication) или использовать Micrometer `@Counted` annotations.

---

## 9. Protected Variations

> **Принцип:** Защитить систему от изменений путём выделения точек вариации через стабильные интерфейсы.

### ✅ Соблюдается

| Защита                                    | Механизм                          | Что защищает |
|-------------------------------------------|-----------------------------------|--------------|
| BC-02 недоступность                       | Circuit Breaker (Resilience4j) в `InstalledPluginFetchClient` и `PermissionFetchClient` | Gateway от каскадного сбоя при падении BC-02 |
| Thundering herd при недоступности BC-02   | Negative cache sentinel (`__UNAVAILABLE__`, TTL 30s) в обоих кеш-сервисах | Redis от шторма запросов при восстановлении |
| Redis недоступность                       | try-catch вокруг Redis ops в `InstalledPluginCacheService.isInstalled()` и `PermissionCacheService` | Фильтры от Redis-ошибок (graceful degradation) |
| Отсутствие `ServiceTokenPort`             | `FetchClientUtils.fallbackHeaderInterceptor()` в обоих клиентах | REST-клиенты от ошибки при отсутствии service token |
| Неправильный формат `pluginId`            | `FetchClientUtils.PLUGIN_ID_PATTERN` + validate в клиентах | Кеш-ключи от injection, URLs от malformed input |
| Неправильный формат `tenantId`            | UUID pattern validation в `InstalledPluginFetchClient` | Redis-ключи от injection |
| Malformed CloudEvents payload             | `PermissionRevocationEventParser.validatePayload()` (size/length limits) | Kafka consumer от malformed events |
| Duplicate Kafka events                    | Redis dedup key (`revoked-event-processed:`) в `PermissionRevocationEventParser.isDuplicateEvent()` | Кеш от повторной инвалидации |
| Malformed plugin slug                     | `PluginSlugValidator.isValidSlug()` | MCP-маршрутизация и webhook dispatch от injection |
| Invalid configuration                     | `@Validated` + `@NotBlank` / `@Positive` на `GatewayProperties` | Приложение от невалидной конфигурации (fail-fast) |
| Webhook dispatch failure                  | Retry с exponential backoff в `WebhookDispatcher` | Доставка webhook при временных сбоях pod |
| JWT tampering                             | NimbusDS JWKS validation в `PluginAuthFilter` | Система от подделки токенов |
| Null/blank permission names               | `PermissionCacheService.validatePermissionNames()` | Кеш от corrupted data (separator в значении) |
| 404 от BC-02 (plugin не существует)       | Специальная обработка `HttpClientErrorException.NotFound` → `Optional.of(false)` | Кеш от false-negative miss |

### ⚠️ Нарушения

**Нарушение PV-1: Отсутствие circuit breaker для JWKS endpoint**

`PluginAuthFilter.init()` создаёт `JWKSource` с кешированием, но JWKS fetch при холодном старте или истечении кеша не защищён circuit breaker:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PluginAuthFilter.java#L55-58
    JWKSource<SecurityContext> jwkSource =
        JWKSourceBuilder.create(URI.create(jwtConfig.jwksUri()).toURL())
            .cache(jwtConfig.jwksCacheTtlMinutes() * 60L * 1000L, 60_000L)
            .build();
```

Если Keycloak медленный или недоступен, все запросы будут блокироваться на JWKS fetch.

**Рекомендация:** Добавить timeout на JWKS fetch и рассмотреть circuit breaker для JWKS endpoint (или хотя бы `JwksHealthIndicator` для readiness probe — уже есть).

---

**Нарушение PV-2: Отсутствие timeout на proxy-запросы**

`ProxyExecutionService` и `McpProxyService` создают `RestClient` без явных connect/read timeout:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/routing/ProxyExecutionService.java#L34-36
  public ProxyExecutionService(RestClient.Builder restClientBuilder) {
    this.restClient = restClientBuilder.build();
  }
```

Если upstream BC зависнет, поток будет заблокирован на неопределённое время.

**Рекомендование:** Добавить `SimpleClientHttpRequestFactory` с connect/read timeout (как в fetch clients: 3000ms).

---

**Нарушение PV-3: `PermissionEnforcementFilter` не защищён от изменения формата path**

Константа `GATEWAY_PREFIX` дублирована в двух местах:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PermissionIntersectionService.java#L29
  private static final String GATEWAY_PREFIX = "/api/bc-02/gateway/v1/api/";
```

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/filter/PermissionEnforcementFilter.java#L46
  private static final String GATEWAY_PREFIX = "/api/bc-02/gateway/v1/api/";
```

И аналогично в `RouteResolutionService`:

```adapstory-plugin-gateway/src/main/java/com/adapstory/gateway/routing/RouteResolutionService.java#L22
  private static final String GATEWAY_API_PREFIX = "/api/bc-02/gateway/v1/api/";
```

При изменении gateway prefix нужно обновить 3+ класса.

**Рекомендование:** Вынести gateway prefix в `GatewayProperties` или константу в общий utility class.

---

## Итоговая матрица нарушений

| ID    | Паттерн              | Серьёзность | Класс                                      | Рекомендация |
|-------|----------------------|-------------|--------------------------------------------|--------------|
| IE-1  | Information Expert   | Medium      | `PermissionRevocationEventParser`          | Перенести `validatePluginId()` в `FetchClientUtils` |
| IE-2  | Information Expert   | Low         | `PluginAuthFilter`                         | Вынести маппинг JWT claims в `PluginJwtClaimsMapper` |
| C-1   | Controller           | Low         | `PluginRouteResolver`                      | Переименовать в `GatewayProxyController` |
| C-2   | Controller           | Medium      | `WebhookDispatcher`                        | Разделить на `WebhookController` + `WebhookDispatchService` |
| LC-1  | Low Coupling         | High        | `InstalledPluginFetchClient`, `PermissionFetchClient` | Использовать default CB config или вынести фабрику |
| LC-2  | Low Coupling         | High        | `InstalledPluginFetchClient`, `PermissionFetchClient` | Вынести `RestClient` factory в `Bc02ClientConfig` |
| LC-3  | Low Coupling         | Medium      | `PermissionRevocationEventParser`          | Убрать зависимость `cache/` → `client/` |
| LC-4  | Low Coupling         | Low         | Фильтры, контроллеры                       | Заменить `ObjectMapper` injection на bean `GatewayErrorResponseWriter` |
| HC-1  | High Cohesion        | Medium      | `PluginAuthFilter`                         | Вынести JWT processor setup и claims mapping |
| HC-2  | High Cohesion        | Medium      | `WebhookDispatcher`                        | Разделить контроллер и dispatch-сервис |
| HC-3  | High Cohesion        | Low         | `InstalledPluginFetchClient`               | Вынести RestClient/CB creation в config |
| P-1   | Polymorphism         | Medium      | `InstalledPluginCacheService`, `PermissionCacheService` | Ввести `InstalledPluginCachePort`, `PermissionCachePort` |
| P-2   | Polymorphism         | Low         | `InstalledPluginFetchClient`, `PermissionFetchClient` | Ввести `InstalledPluginFetchPort`, `PermissionFetchPort` |
| P-3   | Polymorphism         | Medium      | `IntersectionResult`                       | Sealed interface вместо boolean flags |
| PF-1  | Pure Fabrication     | Medium      | Оба fetch-клиента                          | Создать `Bc02ClientConfig` |
| PF-2  | Pure Fabrication     | Low         | `PluginAuthFilter`                         | Создать `PluginJwtClaimsMapper` |
| I-1   | Indirection          | Low         | Фильтры, контроллеры                       | Bean `GatewayErrorResponseWriter` вместо static + ObjectMapper |
| I-2   | Indirection          | Low         | `PluginInstalledCheckFilter`, `PermissionEnforcementFilter` | Вынести metric tracking в `GatewayMetrics` |
| PV-1  | Protected Variations | Medium      | `PluginAuthFilter`                         | Timeout на JWKS fetch |
| PV-2  | Protected Variations | High        | `ProxyExecutionService`, `McpProxyService` | Добавить connect/read timeout на proxy RestClient |
| PV-3  | Protected Variations | Low         | 3 класса                                   | Вынести `GATEWAY_PREFIX` в константу или properties |

---

## Приоритизированный план улучшений

### P0 — Критические (High severity)

1. **PV-2:** Добавить connect/read timeout на proxy `RestClient` в `ProxyExecutionService` и `McpProxyService`. Без этого зависший upstream BC заблокирует threads.
2. **LC-1 + LC-2 + PF-1:** Вынести общую конфигурацию `RestClient` и `CircuitBreaker` для BC-02 клиентов в `Bc02ClientConfig`. Устраняет дублирование ~80 строк кода.

### P1 — Важные (Medium severity)

3. **IE-1 + LC-3:** Перенести `validatePluginId()` из `PermissionFetchClient` в `FetchClientUtils`. Устраняет кросс-слойную зависимость.
4. **P-1:** Ввести интерфейсы `InstalledPluginCachePort` и `PermissionCachePort` для кеш-сервисов.
5. **P-3:** Заменить `IntersectionResult` на sealed interface с pattern matching.
6. **HC-1 + IE-2:** Вынести JWT processor setup в `JwtProcessorFactory` и claims mapping в `PluginJwtClaimsMapper`.
7. **C-2 + HC-2:** Разделить `WebhookDispatcher` на `WebhookController` + `WebhookDispatchService`.
8. **PV-1:** Добавить защиту (timeout / CB) для JWKS endpoint.

### P2 — Желательные (Low severity)

9. **C-1:** Переименовать `PluginRouteResolver` → `GatewayProxyController`.
10. **LC-4 + I-1:** Создать bean `GatewayErrorResponseWriter` вместо static util + ObjectMapper injection.
11. **PV-3:** Вынести `GATEWAY_PREFIX` в `GatewayProperties` или общую константу.
12. **I-2:** Вынести metric tracking в `GatewayMetrics` bean.
13. **P-2:** Ввести интерфейсы для fetch-клиентов.

---

*Аудит завершён. Отчёт подготовлен на основе анализа 33 production Java-классов микросервиса `adapstory-plugin-gateway`.*
