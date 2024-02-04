# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

p_version = "0.3.4"

with open("README.md") as f:
    long_description = f.read()

setup(
    name="acme-nginx",
    version=p_version,
    author="Konstantin Shcherban",
    author_email="k.scherban@gmail.com",
    packages=find_packages(),
    url="https://github.com/kshcherban/acme-nginx",
    download_url="https://github.com/kshcherban/acme-nginx/tarball/v{0}".format(
        p_version
    ),
    license="GPL v3",
    description="A simple client/tool for Let's Encrypt or any ACME server that issues SSL certificates.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=[
        "tls",
        "ssl",
        "certificate",
        "acme",
        "letsencrypt",
        "nginx",
        "wildcard certificate",
        "wildcard",
    ],
    install_requires=[
        "pyOpenSSL~=20.0",
        "cryptography==39.0.1",
        "pycryptodome~=3.14",
        "boto3~=1.17",
    ],
    entry_points={
        "console_scripts": [
            "acme-nginx = acme_nginx.client:main",
        ]
    },
)
