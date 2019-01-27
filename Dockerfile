FROM jfloff/alpine-python:3.6-slim
ADD . /app/
COPY requirements.txt /requirements.txt
COPY apk-requirements.txt /apk-requirements.txt
RUN /entrypoint.sh
ENTRYPOINT ["python", "/app/acme-runner.py"]