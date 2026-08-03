FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY scripts/ scripts/
COPY config/ config/
COPY data/ data/

EXPOSE 8888
EXPOSE 8889

CMD ["python", "scripts/run_proxy.py"]
