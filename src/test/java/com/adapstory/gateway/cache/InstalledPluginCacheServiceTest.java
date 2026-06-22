package com.adapstory.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;

/**
 * Тесты InstalledPluginCacheService: Redis cache-aside для проверки установки плагинов.
 *
 * <p>Покрывает: cache hit/miss, negative cache sentinel, BC-02 fetch + cache store, eviction,
 * metric callbacks, Redis failures (graceful cache degradation), input validation.
 */
@DisplayName("InstalledPluginCacheService")
class InstalledPluginCacheServiceTest {

  private InstalledPluginCacheService cacheService;
  private InstalledPluginStatusCacheStore cacheStore;
  private InstalledPluginStatusSource statusSource;

  private static final String PLUGIN_ID = "adapstory.assessment.quiz";
  private static final String TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
  private static final String CACHE_KEY = "plugin-gateway:installed:" + PLUGIN_ID + ":" + TENANT_ID;

  @BeforeEach
  void setUp() {
    cacheStore = mock(InstalledPluginStatusCacheStore.class);
    statusSource = mock(InstalledPluginStatusSource.class);

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    cacheService = new InstalledPluginCacheService(cacheStore, statusSource, properties);
  }

  @Nested
  @DisplayName("Cache hit scenarios")
  class CacheHit {

    @Test
    @DisplayName("should return true when cache contains 'true'")
    void should_returnTrue_when_cachedTrue() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.of("true"));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
      verify(statusSource, never()).fetchInstalledStatus(anyString(), anyString());
    }

    @Test
    @DisplayName("should return false when cache contains 'false'")
    void should_returnFalse_when_cachedFalse() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.of("false"));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      verify(statusSource, never()).fetchInstalledStatus(anyString(), anyString());
    }

    @Test
    @DisplayName("should return empty when negative cache sentinel is stored")
    void should_returnEmpty_when_negativeCacheSentinel() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.of("__UNAVAILABLE__"));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isEmpty();
      verify(statusSource, never()).fetchInstalledStatus(anyString(), anyString());
    }

    @Test
    @DisplayName("should invoke cacheHit callback on hit")
    void should_invokeCacheHitCallback_when_cacheHit() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.of("true"));
      AtomicInteger hitCount = new AtomicInteger(0);

      // Act
      cacheService.isInstalled(PLUGIN_ID, TENANT_ID, hitCount::incrementAndGet, null);

      // Assert
      assertThat(hitCount.get()).isEqualTo(1);
    }
  }

  @Nested
  @DisplayName("Cache miss scenarios")
  class CacheMiss {

    @Test
    @DisplayName("should fetch from BC-02 and cache result on miss")
    void should_fetchAndCache_when_cacheMiss() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.empty());
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.of(true));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
      verify(cacheStore).put(eq(CACHE_KEY), eq("true"), eq(Duration.ofMinutes(5)));
    }

    @Test
    @DisplayName("should cache 'false' when BC-02 says not installed")
    void should_cacheFalse_when_bc02SaysNotInstalled() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.empty());
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.of(false));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      verify(cacheStore).put(eq(CACHE_KEY), eq("false"), eq(Duration.ofMinutes(5)));
    }

    @Test
    @DisplayName("should store negative sentinel when BC-02 unavailable")
    void should_storeNegativeSentinel_when_bc02Unavailable() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.empty());
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.empty());

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isEmpty();
      verify(cacheStore).put(eq(CACHE_KEY), eq("__UNAVAILABLE__"), eq(Duration.ofSeconds(30)));
    }

    @Test
    @DisplayName("should invoke cacheMiss callback on miss")
    void should_invokeCacheMissCallback_when_cacheMiss() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.empty());
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.of(true));
      AtomicInteger missCount = new AtomicInteger(0);

      // Act
      cacheService.isInstalled(PLUGIN_ID, TENANT_ID, null, missCount::incrementAndGet);

      // Assert
      assertThat(missCount.get()).isEqualTo(1);
    }
  }

  @Nested
  @DisplayName("Redis failure — graceful cache degradation")
  class RedisFailure {

    @Test
    @DisplayName("should fetch from BC-02 when Redis read fails")
    void should_fetchFromBc02_when_redisReadFails() {
      // Arrange
      when(cacheStore.find(CACHE_KEY))
          .thenThrow(new RedisConnectionFailureException("Connection refused"));
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.of(true));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
    }

    @Test
    @DisplayName("should not throw when Redis write fails after BC-02 fetch")
    void should_notThrow_when_redisWriteFails() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.empty());
      when(statusSource.fetchInstalledStatus(PLUGIN_ID, TENANT_ID)).thenReturn(Optional.of(true));
      org.mockito.Mockito.doThrow(new RedisConnectionFailureException("Connection refused"))
          .when(cacheStore)
          .put(eq(CACHE_KEY), eq("true"), eq(Duration.ofMinutes(5)));

      // Act — should not throw
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
    }
  }

  @Nested
  @DisplayName("Eviction")
  class Eviction {

    @Test
    @DisplayName("should delete cache entry on evict")
    void should_deleteCacheEntry_on_evict() {
      // Act
      cacheService.evict(PLUGIN_ID, TENANT_ID);

      // Assert
      verify(cacheStore).delete(CACHE_KEY);
    }

    @Test
    @DisplayName("should not throw when Redis delete fails during eviction")
    void should_notThrow_when_redisDeleteFails() {
      // Arrange
      org.mockito.Mockito.doThrow(new RedisConnectionFailureException("Connection refused"))
          .when(cacheStore)
          .delete(anyString());

      // Act — should not throw
      cacheService.evict(PLUGIN_ID, TENANT_ID);
    }
  }

  @Nested
  @DisplayName("Input validation — buildKey")
  class InputValidation {

    @Test
    @DisplayName("should throw NullPointerException for null pluginId")
    void should_throw_when_pluginIdNull() {
      assertThatThrownBy(() -> cacheService.isInstalled(null, TENANT_ID))
          .isInstanceOf(NullPointerException.class)
          .hasMessageContaining("pluginId must not be null");
    }

    @Test
    @DisplayName("should throw NullPointerException for null tenantId")
    void should_throw_when_tenantIdNull() {
      assertThatThrownBy(() -> cacheService.isInstalled(PLUGIN_ID, null))
          .isInstanceOf(NullPointerException.class)
          .hasMessageContaining("tenantId must not be null");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for pluginId with unsafe characters")
    void should_throw_when_pluginIdUnsafe() {
      assertThatThrownBy(() -> cacheService.isInstalled("plugin:id", TENANT_ID))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("unsafe characters");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for tenantId with unsafe characters")
    void should_throw_when_tenantIdUnsafe() {
      assertThatThrownBy(() -> cacheService.isInstalled(PLUGIN_ID, "tenant:id"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("unsafe characters");
    }
  }

  @Nested
  @DisplayName("Overloaded isInstalled without callbacks")
  class OverloadedMethod {

    @Test
    @DisplayName("should delegate to full method with null callbacks")
    void should_delegate_to_fullMethod() {
      // Arrange
      when(cacheStore.find(CACHE_KEY)).thenReturn(Optional.of("true"));

      // Act
      Optional<Boolean> result = cacheService.isInstalled(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
    }
  }
}
