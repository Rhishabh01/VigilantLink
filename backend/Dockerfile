# Use the official Microsoft Playwright image with Python
FROM mcr.microsoft.com/playwright/python:v1.43.0-jammy

# Set environment variables for production
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PORT 8000

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ensure playwright chromium is installed
# (The base image has browsers, but this ensures they match the installed package version)
RUN playwright install chromium

# Copy the application code
COPY . .

# Start the application using uvicorn, binding to the PORT provided by Railway
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
