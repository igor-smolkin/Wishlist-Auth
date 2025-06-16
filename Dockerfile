FROM gradle:8.1.1-jdk17 AS build
COPY . /auth
WORKDIR /auth
RUN chmod +x gradlew && ./gradlew bootJar

FROM openjdk:17-jdk-slim
COPY --from=build /auth/build/libs/auth.jar auth.jar
ENTRYPOINT ["java", "-jar", "auth.jar"]