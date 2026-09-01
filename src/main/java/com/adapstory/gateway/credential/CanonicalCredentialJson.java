package com.adapstory.gateway.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

public final class CanonicalCredentialJson {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();

  private CanonicalCredentialJson() {}

  /** Serializes JSON with recursively sorted object keys and no insignificant whitespace. */
  public static byte[] bytes(JsonNode value) {
    try {
      return OBJECT_MAPPER.writeValueAsBytes(sort(value));
    } catch (JsonProcessingException exception) {
      throw new CredentialCapabilityRejectedException("credential request is not canonical JSON");
    }
  }

  /** Computes the lowercase SHA-256 digest of canonical JSON. */
  public static String sha256(JsonNode value) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes(value)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /** Computes the lowercase SHA-256 digest of a UTF-8 string. */
  public static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static JsonNode sort(JsonNode value) {
    if (value.isObject()) {
      ObjectNode result = OBJECT_MAPPER.createObjectNode();
      List<String> names = new ArrayList<>();
      value.fieldNames().forEachRemaining(names::add);
      names.sort(Comparator.naturalOrder());
      for (String name : names) {
        result.set(name, sort(value.get(name)));
      }
      return result;
    }
    if (value.isArray()) {
      ArrayNode result = OBJECT_MAPPER.createArrayNode();
      value.forEach(element -> result.add(sort(element)));
      return result;
    }
    return value.deepCopy();
  }
}
