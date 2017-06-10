# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

p_version = '0.0.6'

setup(
    name = 'acme-nginx',
    version = p_version,
    author = 'Konstantin Shcherban',
    author_email = 'k.scherban@gmail.com',
    packages = find_packages(),
    url = 'https://github.com/kshcherban/acme-nginx',
    download_url = 'https://github.com/kshcherban/acme-nginx/tarball/v{0}'.format(p_version),
    license = 'GPL v3',
    description = 'A simple client/tool for Let\'s Encrypt or any ACME server that issues SSL certificates.',
    keywords = ["tls", "ssl", "certificate", "acme", "letsencrypt", "nginx"],
    install_requires = [
        "pyOpenSSL>=0.13",
        "pycrypto>=2.6"
    ],
    entry_points = {
        'console_scripts': [
            'acme-nginx = acme_nginx.client:main',
        ]
    }
)
