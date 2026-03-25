package com.adapstory.gateway;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Базовый класс для интеграционных тестов Plugin Gateway.
 *
 * <p>Singleton-контейнеры: Redis 7, Kafka 7.6.0. WireMock: JWKS (Keycloak stub) + target BC mock.
 * Стартуют один раз за весь тестовый прогон.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractGatewayIntegrationTest {

  // --- Singleton Testcontainers ---

  @SuppressWarnings("resource")
  static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  static final KafkaContainer KAFKA =
      new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.6.0"));

  // --- Static WireMock servers ---

  static final WireMockServer JWKS_WIREMOCK = new WireMockServer(0);
  static final WireMockServer BC_WIREMOCK = new WireMockServer(0);
  static final WireMockServer BC02_WIREMOCK = new WireMockServer(0);

  // --- RSA key pair for JWT signing ---

  static RSAKey rsaKey;
  static JWSSigner jwsSigner;

  static {
    try {
      rsaKey = new RSAKeyGenerator(2048).keyID("test-key-id").generate();
      jwsSigner = new RSASSASigner(rsaKey);
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to generate RSA key pair for tests", ex);
    }

    REDIS.start();
    KAFKA.start();

    JWKS_WIREMOCK.start();
    BC_WIREMOCK.start();
    BC02_WIREMOCK.start();

    String jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();
    JWKS_WIREMOCK.stubFor(WireMock.get("/certs").willReturn(WireMock.okJson(jwksJson)));
  }

  @LocalServerPort protected int port;

  @Autowired protected StringRedisTemplate redisTemplate;

  protected RestClient testClient;

  @BeforeEach
  void initTestClient() {
    testClient = RestClient.builder().baseUrl("http://localhost:" + port).build();
  }

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    // Redis
    registry.add("spring.data.redis.host", REDIS::getHost);
    registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));

    // Kafka
    registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);

    // JWKS → WireMock
    registry.add("gateway.jwt.jwks-uri", () -> JWKS_WIREMOCK.baseUrl() + "/certs");

    // Route: content → BC WireMock
    registry.add("gateway.routes.content", BC_WIREMOCK::baseUrl);

    // BC-02 permissions endpoint → BC02 WireMock (SEC-3.2)
    registry.add("gateway.bc02.base-url", BC02_WIREMOCK::baseUrl);
  }

  @BeforeEach
  void flushRedis() {
    Set<String> keys = redisTemplate.keys("plugin:permissions:*");
    if (keys != null && !keys.isEmpty()) {
      redisTemplate.delete(keys);
    }
  }

  @BeforeEach
  void resetBc02WireMock() {
    BC02_WIREMOCK.resetAll();
  }

  /**
   * Настраивает WireMock-заглушку BC-02 для возврата permissions плагина.
   *
   * @param pluginId идентификатор плагина
   * @param permissions список scope-имён для ответа
   */
  protected static void stubBc02Permissions(String pluginId, List<String> permissions) {
    String permJson =
        permissions.stream().map(p -> "\"" + p + "\"").reduce((a, b) -> a + "," + b).orElse("");
    String body =
        String.format(
            "{\"data\":{\"pluginId\":\"%s\",\"permissions\":[%s]},\"messages\":[],\"error\":null}",
            pluginId, permJson);

    BC02_WIREMOCK.stubFor(
        WireMock.get("/api/bc-02/plugin-lifecycle/v1/" + pluginId + "/permissions")
            .willReturn(WireMock.okJson(body)));
  }

  /** Create HTTP headers with a valid JWT Bearer token. */
  protected HttpHeaders bearerHeaders(String jwt) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(jwt);
    return headers;
  }

  // --- JWT helper methods ---

  /**
   * Build a valid JWT token with the given claims.
   *
   * @param pluginId full plugin identifier
   * @param tenantId tenant identifier
   * @param permissions list of permissions
   * @param trustLevel trust level (e.g., "CORE")
   * @return serialized JWT string
   */
  protected static String buildValidJwt(
      String pluginId, String tenantId, List<String> permissions, String trustLevel) {
    try {
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin:" + pluginId)
              .issuer("https://auth.adapstory.com/realms/plugins")
              .audience("adapstory-core")
              .claim("plugin_id", pluginId)
              .claim("adapstory_tenant_id", tenantId)
              .claim("permissions", permissions)
              .claim("trust_level", trustLevel)
              .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
              .issueTime(Date.from(Instant.now()))
              .build();

      SignedJWT signedJWT =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
      signedJWT.sign(jwsSigner);
      return signedJWT.serialize();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build JWT", ex);
    }
  }

  /**
   * Build a JWT signed with a DIFFERENT RSA key (invalid signature).
   *
   * @param pluginId full plugin identifier
   * @param tenantId tenant identifier
   * @param permissions list of permissions
   * @param trustLevel trust level
   * @return serialized JWT string with invalid signature
   */
  protected static String buildInvalidSignatureJwt(
      String pluginId, String tenantId, List<String> permissions, String trustLevel) {
    try {
      RSAKey otherKey = new RSAKeyGenerator(2048).keyID("wrong-key-id").generate();
      JWSSigner otherSigner = new RSASSASigner(otherKey);

      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin:" + pluginId)
              .issuer("https://auth.adapstory.com/realms/plugins")
              .audience("adapstory-core")
              .claim("plugin_id", pluginId)
              .claim("adapstory_tenant_id", tenantId)
              .claim("permissions", permissions)
              .claim("trust_level", trustLevel)
              .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
              .issueTime(Date.from(Instant.now()))
              .build();

      SignedJWT signedJWT =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(otherKey.getKeyID()).build(), claims);
      signedJWT.sign(otherSigner);
      return signedJWT.serialize();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build invalid signature JWT", ex);
    }
  }

  /**
   * Build an expired JWT token for negative tests.
   *
   * @param pluginId full plugin identifier
   * @param tenantId tenant identifier
   * @param permissions list of permissions
   * @param trustLevel trust level
   * @return serialized expired JWT string
   */
  protected static String buildExpiredJwt(
      String pluginId, String tenantId, List<String> permissions, String trustLevel) {
    try {
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin:" + pluginId)
              .issuer("https://auth.adapstory.com/realms/plugins")
              .audience("adapstory-core")
              .claim("plugin_id", pluginId)
              .claim("adapstory_tenant_id", tenantId)
              .claim("permissions", permissions)
              .claim("trust_level", trustLevel)
              .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
              .issueTime(Date.from(Instant.now().minusSeconds(7200)))
              .build();

      SignedJWT signedJWT =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
      signedJWT.sign(jwsSigner);
      return signedJWT.serialize();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build expired JWT", ex);
    }
  }
}
