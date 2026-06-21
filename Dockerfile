FROM python:3.11-slim

WORKDIR /app

# req
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy
COPY . .

# run
CMD sh -c "gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:${PORT:-8000}"
