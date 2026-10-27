FROM python:3.11

RUN python -m pip install --no-cache-dir PyKMIP==0.10.0

COPY client.py /client.py
ENTRYPOINT ["python", "/client.py"]
