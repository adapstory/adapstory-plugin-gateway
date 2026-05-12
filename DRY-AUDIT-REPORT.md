# DRY Audit Report — adapstory-plugin-gateway

**Дата:** 2025-07-12  
**Аудитор:** DRY Auditor (automated)  
**BC:** Plugin Gateway (BC-02 Gateway)

---

## Сводная таблица

| # | Уровень | Нарушение | Серьёзность | Файл(ы) | Статус |
|---|---------|-----------|-------------|---------|--------|
| DRY-PG-01 | Build | `distributionManagement` + `repositories` — копипаст Nexus URL | 🟡 MEDIUM | `pom.xml` | Должно быть в master-pom |
| DRY-PG-02 | Infrastructure | JWT validation pipeline (NimbusDS) — JwtProcessorFactory создан локально, а не в shared security starter | 🟡 MEDIUM | `config/JwtProcessorFactory.java` | Не переиспользует shared JWT infra |
| DRY-PG-03 | Infrastructure | SecurityFilterChain — полностью кастомная конфигурация, не использует shared starter-security | 🟢 LOW | `config/SecurityConfig.java` | Обосновано: gateway — особый случай (proxy, не REST API) |
| DRY-PG-04 | Domain | `GatewayErrorResponse` — формат ошибки, дублирующий `AdapstoryResponse` из shared commons | 🟡 MEDIUM | `dto/GatewayErrorResponse.java` | Не использует shared error format |

---

## Детали

### DRY-PG-01: distributionManagement копипаст

**Проблема:** Идентична DRY-ID-02.

**Рекомендация:** Вынести в `adapstory-master-pom`.

---

### DRY-PG-02: JWT validation pipeline не в shared starter

**Проблема:** `JwtProcessorFactory` создаёт NimbusDS JWT processor локально. Другие сервисы (BFF admin/school/student) используют `ReactiveOidcServiceImpl` с похожей JWKS логикой.

```java
// JwtProcessorFactory.java — локальная реализация
JWKSource<SecurityContext> jwkSource =
    JWKSourceBuilder.create(URI.create(jwtConfig.jwksUri()).toURL())
        .cache(jwtConfig.jwksCacheTtlMinutes() * 60L * 1000L, 60_000L)
        .build();
```

**Кросс-сервисное дублирование:** plugin-gateway, bff-admin, bff-school, bff-student — все имеют свою JWT/JWKS логику.

**Рекомендация:** Вынести общую JWT validation конфигурацию в `adapstory-starter-security` или отдельный starter.

---

### DRY-PG-04: GatewayErrorResponse vs AdapstoryResponse

**Проблема:** `GatewayErrorResponse` — record с полями `timestamp, status, error, message, path, requestId, details`. Это дублирует контракт `AdapstoryResponse` из `adapstory-commons`, который уже используется другими BC.

**Рекомендация:** Использовать `AdapstoryResponse` из shared commons или создать типизированный error variant в commons.

---

## Позитивные находки (DRY-compliant)

- ✅ **IntegrationHeaders** — `HeaderInjectionFilter` корректно использует `IntegrationHeaders.HEADER_REQUEST_ID`, `HEADER_CORRELATION_ID` и т.д.
- ✅ **IntegrationIdValidator** — используется для валидации UUID
- ✅ **CloudEventEnvelopeConverter** — Kafka consumer (`PermissionCacheInvalidationListener`) использует shared converter
- ✅ **Shared starters** — подключены: `adapstory-commons`, `starter-kafka`, `starter-logging`, `starter-monitoring`, `starter-resilience`, `starter-security`, `starter-tracing`, `starter-web`, `starter-testing`
- ✅ **BOM versions** — все версии через parent
- ✅ **ProxyHeaderUtils** — внутренний utility для hop-by-hop headers, корректно выделен из McpProxyService и ProxyExecutionService
