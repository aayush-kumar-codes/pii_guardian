FROM python:3.9-slim

WORKDIR /app

COPY requirements/aggregator.txt .
RUN pip install --no-cache-dir -r aggregator.txt

COPY src/aggregator /app/aggregator
COPY src/utils/logger.py /app/utils/
COPY src/__init__.py /app/src/__init__.py
COPY src/utils/__init__.py /app/utils/

CMD ["python", "-m", "aggregator.main"]