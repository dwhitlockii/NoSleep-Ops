FROM python:3.9-slim

# Install system dependencies including Docker CLI
RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    procps \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY ./web-monitor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ML analytics modules from parent directory
COPY ./ml_analytics ./ml_analytics

# Copy application files
COPY ./web-monitor .

# Create directories for logs and database
RUN mkdir -p /app/logs /app/data

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Run the application
CMD ["python", "app.py"] 