# ZTG 서비스 공용 실행 이미지 (D2 컨테이너화).
#
# 왜 이 방식: 핫패스 JVM 4개(gateway/pdp/pip/resource-api)를 같은 도커 네트워크에 올려
# 내부 mTLS 통신을 리눅스 브리지에 태운다 → tcpdump 하나로 mTLS 핸드셰이크까지 캡처(JD 정조준).
#
# bootJar는 호스트에서 ./gradlew :<mod>:bootJar로 먼저 빌드한다(up-mtls-docker.ps1이 수행).
# compose의 build.context = 각 모듈 폴더, dockerfile = ../docker/Dockerfile 로 이 파일을 공유한다.
# COPY 글롭은 *-SNAPSHOT.jar만 매치한다 — bootJar(예: gateway-0.0.1-SNAPSHOT.jar)만 잡히고
# plain jar(-SNAPSHOT-plain.jar)는 접미사가 달라 제외된다.
FROM eclipse-temurin:21-jre

WORKDIR /app
COPY build/libs/*-SNAPSHOT.jar app.jar

# 인증서는 이미지에 굽지 않고 런타임 볼륨(/certs)으로 마운트한다(compose). ZTG_CERT_DIR로 위치 주입.
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
