# Adapstory Plugin Gateway

Lightweight REST proxy for plugin-to-core BC communication with JWT authentication and permission enforcement.

## Role

Single ingress for plugin traffic into the Adapstory platform core. Validates JWT tokens issued by Identity (BC-16), enforces plugin manifest permissions, and forwards requests to the appropriate bounded context.

## Stack

- Java 25 + Spring Boot 4 (managed by `adapstory-master-pom`)
- nimbus-jose-jwt, Resilience4j (Spring Cloud CircuitBreaker)
- OpenTelemetry (OTLP)

## Build

```bash
./mvnw clean install           # full build with quality gates
./mvnw test -Pfast             # fast path, no checks
./mvnw spotless:apply          # auto-format
```

## Run

```bash
./mvnw spring-boot:run
# or
docker build -t adapstory-plugin-gateway . && docker run --rm -p 8080:8080 adapstory-plugin-gateway
```

## Related

- Manifest schema: `adapstory-shared-libs` (`adapstory-plugin-schema`)
- Identity / JWT issuer: `adapstory-identity` (BC-16)
- Plugin lifecycle: `adapstory-plugin-lifecycle` (BC-02)
