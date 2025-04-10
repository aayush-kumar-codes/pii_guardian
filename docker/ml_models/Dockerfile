FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for spaCy
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ml.txt .
RUN pip install --no-cache-dir -r ml.txt

# Install PyTorch - adjust as needed for GPU support
RUN pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
# Install transformers for embedding model
RUN pip install transformers

# Download spaCy models
COPY download_models.py .
RUN python download_models.py

COPY src/ml_service /app/ml_service
COPY src/models /app/models
COPY src/utils /app/utils
COPY src/services /app/services
COPY src/__init__.py /app/src/__init__.py
COPY src/utils/__init__.py /app/utils/__init__.py
COPY src/models/__init__.py /app/models/__init__.py
COPY src/services/__init__.py /app/services/__init__.py

CMD ["python", "-m", "ml_service.main"]