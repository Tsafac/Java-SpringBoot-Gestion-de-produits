# --- Etape 1: Construction
FROM maven:3.8.5-openjdk-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY /src ./src
RUN mvn clean package -DskipTests

# --- ETAPE 2 : Runtime
FROM gcr.io/distroless/java17-debian11
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
COPY src/main/resources/.env .env
ENTRYPOINT ["java", "-jar", "app.jar"]