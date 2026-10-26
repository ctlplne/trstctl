# A PyKMIP server for the KMIP reconciliation source's independent proof
# (A124). Test-only: kmipsource_pykmip_test.go builds it, mounts its own TLS
# material and seeds objects with seed.py. PyKMIP 0.10 needs Python 3.11 (it
# calls ssl.wrap_socket, which 3.12 removed) and SQLAlchemy 1.x.
FROM python:3.11-slim-bookworm
RUN pip install --no-cache-dir "pykmip==0.10.0" "sqlalchemy==1.4.54" "cryptography==42.0.8"
RUN mkdir -p /opt/kmip/policies
COPY seed.py /opt/kmip/seed.py
EXPOSE 5696
