# ARC Blast Shield — Vultr deployment image
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py agent.py llm.py policy.py sandbox.py ./
COPY static/ ./static/
COPY sample_data.csv ./
RUN mkdir -p runs
ENV PORT=8080
EXPOSE 8080
# VULTR_API_KEY is injected at runtime (env var on the instance), never baked in.
CMD ["python", "server.py"]
