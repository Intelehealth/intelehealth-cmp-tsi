FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Kolkata

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY python_port/requirements.txt /app/python_port/requirements.txt
RUN pip install --no-cache-dir -r /app/python_port/requirements.txt

COPY python_port /app/python_port
COPY web /app/web

RUN mkdir -p /var/lib/tsi/exports && chown -R app:app /app /var/lib/tsi

USER app
WORKDIR /app/python_port

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"

CMD ["uvicorn", "dpdpcms_py.main:app", "--host", "0.0.0.0", "--port", "8080"]
