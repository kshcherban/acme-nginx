FROM python:3.7 as build

WORKDIR /opt
RUN pip install pyinstaller
COPY . /opt
RUN pip wheel -r requirements.txt
RUN pip install -r /opt/requirements.txt && \
    python setup.py install && \
    pyinstaller -sF ./acme-runner.py


FROM python:3.7-slim

COPY --from=build /opt /opt

WORKDIR /opt
RUN pip install -r /opt/requirements.txt -f /opt && \
    python setup.py install && \
    cp dist/acme-runner /usr/bin/ && \
    rm -rf /opt/* /root/.cache

ENTRYPOINT ["/usr/local/bin/acme-nginx"]
