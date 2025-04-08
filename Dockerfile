FROM python:3.13 AS build

WORKDIR /opt
RUN pip install --no-cache-dir pyinstaller setuptools
COPY . /opt
RUN pip wheel -r requirements.txt
RUN pip install --no-cache-dir -r /opt/requirements.txt && \
    python setup.py install && \
    pyinstaller -sF ./acme-runner.py


FROM python:3.13-slim

COPY --from=build /opt /opt

WORKDIR /opt
RUN pip install --no-cache-dir setuptools && \
    pip install --no-cache-dir -r /opt/requirements.txt -f /opt && \
    python setup.py install && \
    cp dist/acme-runner /usr/bin/ && \
    rm -rf /opt/* /root/.cache

ENTRYPOINT ["/usr/local/bin/acme-nginx"]
