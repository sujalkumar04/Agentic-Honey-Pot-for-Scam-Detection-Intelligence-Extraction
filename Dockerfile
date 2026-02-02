FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Render uses PORT environment variable
ENV PORT=10000
EXPOSE ${PORT}

# Start server with dynamic port binding
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}
