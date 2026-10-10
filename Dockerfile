FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY pyproject.toml .

# Install Python requirements
RUN pip install --no-cache-dir fastapi uvicorn pydantic pyyaml pytest rich

# Copy codebase
COPY . .

# Run tests during build verification
RUN python -m pytest tests/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
