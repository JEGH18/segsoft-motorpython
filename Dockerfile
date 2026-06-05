FROM python:3.11-slim
WORKDIR /app

RUN addgroup --system pdgseg && adduser --system --ingroup pdgseg pdgseg

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

COPY app ./app

RUN chown -R pdgseg:pdgseg /app
USER pdgseg

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
