package com.adapstory.gateway.credential;

import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = CredentialLifecycleController.class)
@ConditionalOnProperty(name = "gateway.credential-lifecycle.enabled", havingValue = "true")
public final class CredentialLifecycleExceptionHandler {

  @ExceptionHandler(CredentialCapabilityRejectedException.class)
  ResponseEntity<Map<String, String>> denied() {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("type", "credential_authorization_denied"));
  }
}
