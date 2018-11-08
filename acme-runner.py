#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Convenience wrapper for running acme-nginx directly from source tree."""

from acme_nginx.client import main
# uncomment this line for pyinstaller, this is boto3 dependency that pyinstaller ignores
#import configparser

if __name__ == '__main__':
    main()
