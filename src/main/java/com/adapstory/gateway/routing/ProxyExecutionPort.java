package com.adapstory.gateway.routing;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

interface ProxyExecutionPort {

  void execute(HttpServletRequest request, HttpServletResponse response, String targetUri)
      throws IOException;
}
