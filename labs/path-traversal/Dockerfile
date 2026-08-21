# Intentionally vulnerable training target. Runs only on the isolated_labs
# internal network. No dependencies beyond the Python standard library.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

# Seed a public document root and a sibling secret dir the app must NOT expose.
# Path traversal (../) escapes /srv/public to reach /srv/secret/flag.txt.
COPY seed/public/ /srv/public/
COPY seed/secret/ /srv/secret/

# Drop privileges; the lab needs no write access at runtime.
RUN useradd --no-create-home --uid 10001 labuser
USER labuser

ENV LAB_PUBLIC_DIR=/srv/public
EXPOSE 5000
CMD ["python", "/app/app.py"]
