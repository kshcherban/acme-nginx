# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name='acme-nginx',
    version='0.0.3',
    author=u'Konstantin Shcherban',
    packages = find_packages(),
    url='https://github.com/kshcherban/acme-nginx',
    download_url = 'https://github.com/kshcherban/acme-nginx/tarball/v0.0.3',
    license='GPL v3',
    description='A simple client/tool for Let\'s Encrypt or any ACME server that issues SSL certificates.',
    long_description=open("README.md").read(),
    keywords=["tls", "ssl", "certificate", "acme", "letsencrypt", "nginx"],
    install_requires=open("requirements.txt").read().split("\n"),
    entry_points={
        'console_scripts': [
            'acme-nginx = acme_nginx.client:main',
        ]
    }
)
