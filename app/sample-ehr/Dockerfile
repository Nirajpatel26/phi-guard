# One image, three services. SERVICE selects the module: patient_api | claims_api | eligibility_api
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SERVICE=patient_api

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY ehr/ ./ehr/
COPY data/patients.json ./data/patients.json

# Non-root, numeric UID so Kubernetes runAsNonRoot can verify it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin ehr
USER 10001

EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn ehr.${SERVICE}:app --host 0.0.0.0 --port 8000 --no-access-log"]
