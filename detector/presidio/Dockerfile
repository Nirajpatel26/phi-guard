# Build from the repo root:  docker build -f detector/presidio/Dockerfile -t phi-guard/phi-scanner:0.1.0 .
FROM python:3.11-slim

ARG SPACY_MODEL=en_core_web_lg
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SPACY_MODEL=${SPACY_MODEL} PHI_ENGINE=presidio OUTPUT_DIR=/data

WORKDIR /app
COPY detector/presidio/requirements.txt .
RUN pip install -r requirements.txt && python -m spacy download ${SPACY_MODEL}

COPY detector/__init__.py detector/__init__.py
COPY detector/presidio/ detector/presidio/

RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin scanner
USER 10002
EXPOSE 8080
CMD ["uvicorn", "detector.presidio.scanner_service:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
