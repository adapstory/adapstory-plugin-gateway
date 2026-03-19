FROM eclipse-temurin:21-jre-alpine AS runtime

RUN apk --no-cache upgrade

WORKDIR /app
COPY target/adapstory-plugin-gateway-*-exec.jar /app/app.jar
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
EXPOSE 8090
ENV JAVA_OPTS="-XX:+UseZGC -XX:MaxRAMPercentage=75.0"
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:8090/actuator/health/liveness || exit 1
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
