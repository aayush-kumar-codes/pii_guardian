FROM python:3.9-slim

WORKDIR /app

COPY requirements/regex.txt .
RUN pip install --no-cache-dir -r regex.txt

COPY src/regex_service /app/regex_service
COPY src/utils /app/utils
COPY src/__init__.py /app/src/__init__.py

CMD ["python", "-m", "regex_service.main"]