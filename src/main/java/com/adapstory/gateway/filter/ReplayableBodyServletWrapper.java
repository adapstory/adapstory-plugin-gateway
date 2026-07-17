package com.adapstory.gateway.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/** Replayable immutable request body used after bounded security inspection. */
final class ReplayableBodyServletWrapper extends HttpServletRequestWrapper {

  private final byte[] body;

  ReplayableBodyServletWrapper(HttpServletRequest request, byte[] body) {
    super(request);
    this.body = body.clone();
  }

  @Override
  public ServletInputStream getInputStream() {
    ByteArrayInputStream input = new ByteArrayInputStream(body);
    return new ServletInputStream() {
      @Override
      public boolean isFinished() {
        return input.available() == 0;
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setReadListener(ReadListener listener) {
        if (listener == null) {
          throw new IllegalArgumentException("read listener must not be null");
        }
      }

      @Override
      public int read() {
        return input.read();
      }
    };
  }

  @Override
  public java.io.BufferedReader getReader() {
    return new java.io.BufferedReader(
        new java.io.InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
  }
}
