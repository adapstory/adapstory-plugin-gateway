package com.adapstory.gateway;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SurefireDeterminismContractTest {

  @Test
  @DisplayName("the canonical suite must expose the first failing attempt")
  void should_notRerunFailingTests_when_canonicalSuiteRuns() throws IOException {
    // Context: a reactor-netty/WireMock cold-start flake was once hidden by one
    // unconditional Surefire rerun, so retry-pass executions appeared green.
    // Decision: prohibit rerunFailingTestsCount in the canonical gateway build.
    // Reason: the fixture now owns an explicit cold-start budget and the portfolio
    // must observe every first-attempt failure as determinism debt.
    // Revisit when: never for the canonical evidence lane; any diagnostic retry
    // belongs in a separate non-gating command that preserves the original result.
    String pom = Files.readString(Path.of("pom.xml"));

    assertFalse(
        pom.contains("<rerunFailingTestsCount>"),
        "canonical test evidence must not convert a first-attempt failure to PASS");
  }
}
