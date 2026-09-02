FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data/ è creata qui (non nel repo, è in .gitignore) così il mount del volume bot-data
# eredita da subito i permessi di botuser invece che diventare proprietà di root al primo avvio
RUN mkdir -p /app/data \
    && useradd -m -r botuser \
    && chown -R botuser:botuser /app
USER botuser

CMD ["python", "-m", "sanitizelinkbot"]
