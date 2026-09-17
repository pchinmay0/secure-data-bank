FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /code

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Run as a normal user, not root
RUN useradd --create-home appuser \
    && mkdir -p /data/uploads \
    && chown appuser:appuser /data/uploads
COPY app/ ./app/
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]