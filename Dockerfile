FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN echo '#!/bin/sh\n\
echo ">>> SulgX Panel is starting on port ${PORT:-8000}"\n\
exec gunicorn -k uvicorn.workers.UvicornWorker main:app --bind "0.0.0.0:${PORT:-8000}"' > /start.sh && chmod +x /start.sh

EXPOSE 8000

CMD ["/start.sh"]
