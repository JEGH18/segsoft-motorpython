FROM python:3.11-slim
WORKDIR /app

RUN addgroup --gid 10001 --system pdgseg && adduser --uid 10001 --system --ingroup pdgseg pdgseg

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

COPY app ./app

RUN chown -R pdgseg:pdgseg /app \
    && mkdir -p /tmp/pdgseg-sandbox \
    && chown pdgseg:pdgseg /tmp/pdgseg-sandbox
USER pdgseg

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
