package com.adapstory.gateway.routing;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import org.springframework.http.HttpHeaders;

/** Transport boundary for a long-lived, incrementally flushed plugin event stream. */
interface EventStreamProxyPort {

  void stream(
      HttpHeaders requestHeaders,
      HttpServletResponse response,
      OutputStream downstreamBody,
      String targetUri)
      throws IOException;
}
