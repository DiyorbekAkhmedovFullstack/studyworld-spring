# Multi-stage build for Spring Boot on Railway

FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

# Copy pom and sources
COPY pom.xml ./
COPY src ./src

# Build application (skip tests for faster deploy)
RUN mvn -B -DskipTests package


FROM eclipse-temurin:21-jre
WORKDIR /app

# Use a non-root user where available (optional)
# USER 1000

# Copy the built jar
COPY --from=build /app/target/*.jar /app/app.jar

# Railway provides PORT env var; expose for clarity
EXPOSE 8080

# Bind to the provided PORT
CMD ["sh", "-c", "java -Dserver.port=${PORT:-8080} -jar /app/app.jar"]

