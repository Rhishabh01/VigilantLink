FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

CMD ["bash", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
