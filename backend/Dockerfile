FROM mcr.microsoft.com/playwright/python:v1.43.0-jammy

# Install libnss3 for Chromium Sandbox
RUN apt-get update && apt-get install -y libnss3 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash pwuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# We mount the code via volumes in dev, but copy it here for prod readiness
COPY . .

# Change ownership to non-root user
RUN chown -R pwuser:pwuser /app

# Switch to non-root user
USER pwuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
