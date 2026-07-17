package com.adapstory.gateway.mcpgrant;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.commons.header.IntegrationIdValidator;
import com.adapstory.gateway.config.Bc02ClientConfig;
import java.util.List;
import java.util.Objects;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/** Performs one all-or-nothing tenant-scoped verification call to Plugin Lifecycle. */
@Component
final class LifecycleProviderBindingVerifier implements ProviderBindingVerifier {

  private static final String VERIFY_PATH = "/api/bc-02/plugin-lifecycle/v1/tools/verify";

  private final RestClient restClient;

  @Autowired
  LifecycleProviderBindingVerifier(
      Bc02ClientConfig bc02ClientConfig, RestClient.Builder restClientBuilder) {
    this(bc02ClientConfig.createBc02RestClient(restClientBuilder));
  }

  LifecycleProviderBindingVerifier(RestClient restClient) {
    this.restClient = Objects.requireNonNull(restClient, "restClient must not be null");
  }

  @Override
  public void verify(String tenantId, String actorId, List<ProviderBindingGrant> bindings) {
    VerificationRequest body =
        new VerificationRequest(bindings.stream().map(VerificationBinding::from).toList());
    try {
      Integer responseStatus =
          restClient
              .post()
              .uri(VERIFY_PATH)
              .header(IntegrationHeaders.HEADER_TENANT_ID, tenantId)
              .header(IntegrationHeaders.HEADER_USER_ID, actorId)
              .header(
                  IntegrationHeaders.HEADER_REQUEST_ID, tracingId(IntegrationHeaders.REQUEST_ID))
              .header(
                  IntegrationHeaders.HEADER_CORRELATION_ID,
                  tracingId(IntegrationHeaders.CORRELATION_ID))
              .body(body)
              .exchange((request, response) -> response.getStatusCode().value());
      if (responseStatus == null) {
        throw new ProviderBindingVerificationException(
            ProviderBindingVerificationException.Reason.UNAVAILABLE);
      }
      int status = responseStatus;
      if (status == HttpStatus.NO_CONTENT.value()) {
        return;
      }
      if (status == HttpStatus.CONFLICT.value()) {
        throw new ProviderBindingVerificationException(
            ProviderBindingVerificationException.Reason.CONFLICT);
      }
      if (status == HttpStatus.UNPROCESSABLE_ENTITY.value()) {
        throw new ProviderBindingVerificationException(
            ProviderBindingVerificationException.Reason.INVALID);
      }
      throw new ProviderBindingVerificationException(
          ProviderBindingVerificationException.Reason.UNAVAILABLE);
    } catch (ProviderBindingVerificationException exception) {
      throw exception;
    } catch (RestClientException exception) {
      throw new ProviderBindingVerificationException(
          ProviderBindingVerificationException.Reason.UNAVAILABLE, exception);
    }
  }

  private static String tracingId(String mdcKey) {
    String existing = IntegrationIdValidator.normalizeUuidV4OrV7(MDC.get(mdcKey));
    return existing == null ? com.adapstory.commons.id.Uuid7.randomUuid().toString() : existing;
  }

  private record VerificationRequest(List<VerificationBinding> providerBindings) {
    private VerificationRequest {
      providerBindings = List.copyOf(providerBindings);
    }
  }

  private record VerificationBinding(
      String pluginSlug,
      String toolName,
      String capability,
      String toolVersion,
      String inputSchemaVersion,
      String inputSchemaDigest,
      String authPolicy,
      String trustLevel,
      String tenantVisibility,
      String status,
      String lastValidatedAt,
      String description) {

    private static VerificationBinding from(ProviderBindingGrant binding) {
      return new VerificationBinding(
          binding.routeSlug(),
          binding.toolName(),
          binding.capability(),
          binding.toolVersion(),
          binding.inputSchemaVersion(),
          binding.inputSchemaDigest(),
          binding.authPolicy(),
          binding.trustLevel(),
          binding.tenantVisibility(),
          binding.status(),
          binding.lastValidatedAt().toString(),
          binding.description());
    }
  }
}
