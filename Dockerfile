FROM harbor.adapstory.com/dockerhub-cache/library/eclipse-temurin@sha256:c707c0d18cb9e8556380719f80d96a7529d0746fbb42143893949b98ed2f8943 AS runtime

RUN apk add --no-cache --upgrade libcrypto3 libssl3 openssl libexpat p11-kit p11-kit-trust

WORKDIR /app
COPY target/adapstory-plugin-gateway-*-exec.jar /app/app.jar
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
EXPOSE 8090
ENV JAVA_OPTS="-XX:+UseZGC -XX:MaxRAMPercentage=75.0"
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:8090/actuator/health/liveness || exit 1
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
