FROM python:3.9-slim

WORKDIR /app

COPY requirements/transformation.txt .
RUN pip install --no-cache-dir -r transformation.txt

COPY src/transformation_service /app/transformation_service
COPY src/services/transformation_service.py /app/services/
COPY src/utils/logger.py /app/utils/
COPY src/__init__.py /app/src/__init__.py
COPY src/utils/__init__.py /app/utils/
COPY src/services/__init__.py /app/services/__init__.py

CMD ["python", "-m", "transformation_service.main"]