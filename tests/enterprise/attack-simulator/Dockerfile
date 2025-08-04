FROM python:3.11-slim

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/scenarios /app/results /app/logs

# Set permissions
RUN chmod +x /app/attack_orchestrator.py

EXPOSE 8000

CMD ["python", "attack_orchestrator.py"]