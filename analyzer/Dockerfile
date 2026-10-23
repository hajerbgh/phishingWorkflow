FROM python:3.10-slim

WORKDIR /app

# On installe explicitement toutes les dépendances nécessaires
RUN pip install --no-cache-dir fastapi uvicorn requests Levenshtein python-multipart pydantic

COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]