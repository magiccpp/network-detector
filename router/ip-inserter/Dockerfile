FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y iputils-ping \
    build-essential \
    libpq-dev \
    lsof \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY ip-inserter.py .

# Run the application
CMD ["python", "-u", "ip-inserter.py", "--config", "/app/config.json"]