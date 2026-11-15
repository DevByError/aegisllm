FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir . && useradd --create-home aegis && mkdir -p /app/logs && chown aegis /app/logs

COPY policy.example.yaml ./policy.yaml
USER aegis
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/aegis/health').status==200 else 1)"

# Point the upstream at your model server with the policy file, for example
# upstream.base_url: http://host.docker.internal:11434/v1 for Ollama on the host.
CMD ["aegisllm", "serve", "--policy", "policy.yaml", "--host", "0.0.0.0", "--port", "8088"]
