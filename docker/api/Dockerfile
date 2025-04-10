FROM python:3.9-slim

WORKDIR /app

COPY requirements/api.txt .
RUN pip install --no-cache-dir -r api.txt

COPY src/api /app/api
COPY src/utils/logger.py /app/utils/
COPY src/__init__.py /app/src/__init__.py
COPY src/utils/__init__.py /app/utils/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]