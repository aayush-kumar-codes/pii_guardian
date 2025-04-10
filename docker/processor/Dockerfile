FROM python:3.9-slim

WORKDIR /app

COPY requirements/processor.txt .
RUN pip install --no-cache-dir -r processor.txt

COPY src/processor /app/processor
COPY src/utils/logger.py /app/utils/
COPY src/__init__.py /app/src/__init__.py
COPY src/utils/__init__.py /app/utils/

EXPOSE 8001

CMD ["uvicorn", "processor.main:app", "--host", "0.0.0.0", "--port", "8001"]