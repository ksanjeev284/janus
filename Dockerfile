FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Expose ports
# 8000 = Web GUI
# 8080 = Proxy
EXPOSE 8000 8080

# Default command: run web server
CMD ["uvicorn", "janus.interface.web.server:app", "--host", "0.0.0.0", "--port", "8000"]
