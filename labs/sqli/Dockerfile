# Intentionally vulnerable training target. Runs only on the isolated_labs
# internal network. No dependencies beyond the Python standard library.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

# Drop privileges; the lab needs no write access at runtime.
RUN useradd --no-create-home --uid 10001 labuser
USER labuser

EXPOSE 5000
CMD ["python", "/app/app.py"]
