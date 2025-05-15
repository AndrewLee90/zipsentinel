FROM python:3.10-slim

# ✅ 필수 패키지 및 압축 해제 도구 설치
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    p7zip-full \
    unrar-free \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libxss1 \
    libasound2 \
    xdg-utils \
    gnupg \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ✅ Chromium 및 ChromeDriver 수동 설치 (Snap 회피)
ENV CHROME_VERSION=122.0.6261.111

RUN curl -sSL https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip -o chrome.zip && \
    unzip chrome.zip && \
    mv chrome-linux64 /opt/chrome && \
    ln -s /opt/chrome/chrome /usr/bin/chromium && \
    rm chrome.zip

RUN curl -sSL https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip -o chromedriver.zip && \
    unzip chromedriver.zip && \
    mv chromedriver-linux64/chromedriver /usr/bin/chromedriver && \
    chmod +x /usr/bin/chromedriver && \
    rm -rf chromedriver.zip chromedriver-linux64

# ✅ 작업 디렉토리 설정
WORKDIR /app

# ✅ 코드 및 의존성 파일 복사
COPY crawler2.1.2.py ./
COPY requirements.txt ./

# ✅ Python 패키지 설치
RUN pip install --upgrade pip && pip install -r requirements.txt

# ✅ 환경 변수 설정
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_BIN=/usr/bin/chromedriver
ENV PYTHONIOENCODING=utf-8
ENV TZ=Asia/Seoul

# ✅ 실행
CMD ["python", "crawler2.1.2.py"]
