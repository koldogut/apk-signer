FROM python:3.11-slim

ENV APP_HOME=/opt/apk-signer \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    PYTHONUNBUFFERED=1

# 35 es la primera version cuyo zipalign admite -P (alineado a 16 KB).
ARG BUILD_TOOLS_VERSION=35.0.0
ARG CMDLINE_ZIP_URL=https://dl.google.com/android/repository/commandlinetools-linux-11479570_latest.zip

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-17-jre \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools" \
    && curl -fL -o /tmp/cmdline-tools.zip "${CMDLINE_ZIP_URL}" \
    && unzip -q /tmp/cmdline-tools.zip -d "${ANDROID_SDK_ROOT}/cmdline-tools" \
    && rm -f /tmp/cmdline-tools.zip \
    && if [ -d "${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools" ]; then \
        mv "${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools" "${ANDROID_SDK_ROOT}/cmdline-tools/latest"; \
      fi \
    && yes | "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" --licenses \
    && "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" \
        "platform-tools" \
        "build-tools;${BUILD_TOOLS_VERSION}" \
    && mkdir -p "${APP_HOME}/tools" \
    && cp "${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}/aapt2" "${APP_HOME}/tools/aapt2" \
    && cp "${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}/lib/apksigner.jar" "${APP_HOME}/tools/apksigner.jar"
# zipalign NO se copia: enlaza dinamicamente contra lib64/libc++.so y fuera de
# su directorio del SDK falla con "error while loading shared libraries".
# secrets.example.json ya apunta ZIPALIGN a la ruta dentro de ANDROID_SDK_ROOT.
# aapt2 si se puede copiar porque va enlazado estaticamente.

COPY requirements.txt ${APP_HOME}/requirements.txt
RUN pip install --no-cache-dir -r ${APP_HOME}/requirements.txt

COPY . ${APP_HOME}

EXPOSE 8001

CMD ["gunicorn", "-b", "0.0.0.0:8001", "app:app"]
