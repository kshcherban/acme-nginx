# acme-nginx

Simple way to get SSL certificates for free.

## Table of Contents

- [Features](#features)
- [Description](#description)
- [ACME v2](#acme-v2)
- [ACME v1](#acme-v1)
- [Installation](#installation)
- [Usage](#usage)
  * [Wildcard certificates](#wildcard-certificates)
  * [Debug](#debug)
  * [Renewal](#renewal)

## Features

* Supports both Python 2 and Python 3
* Works with both ACMEv1 and ACMEv2 protocols
* Can issue [wildcard certificates](https://en.wikipedia.org/wiki/Wildcard_certificate)!
* Easy to use and extend

## Description

This is [ACME](https://ietf-wg-acme.github.io/acme/) client implementation in
Python originally based on https://github.com/diafygi/acme-tiny code.
Now completely different.
It's written in pure Python depends on pyOpenSSL and pycrypto
and the only binary it calls is **ps** to determine nginx master process id
to send `SIGHUP` to it during challenge completion.

As you may not trust this script feel free to check source code,
it's under 700 lines of code.

Script should be run as root on host with running nginx server.
Domain for which you request certificate should point to that host's IP and port
80 should be available from outside if you use HTTP challenge.
Script can generate all keys for you if you don't set them with command line arguments.
Keys are RSA with length of 2048 bytes.
You can specify as many alternative domain names as you wish.
The result PEM file is a **certificate chain** containing your signed
certificate and letsencrypt signed chain. You can use it with nginx.

Should work with Python >= 2.6

## ACME v2

ACME v2 requires more logic so it's not as small as acme v1 script.

ACME v2 is supported partially: only `http-01` and `dns-01` challenges.
Check https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-9.7.6

New protocol is used by default.

`http-01` challenge is passed exactly as in v1 protocol realisation.

`dns-01` currently supports only DigitalOcean, AWS Route53 DNS providers.

Technically nginx is not needed for this type of challenge but script still calls nginx reload by default
because it assumes that you store certificates on the same server where you issue
them. To disable that behavior please specify `--no-reload-nginx` parameter.

AWS Route53 uses `default` profile in session, specifying profile works with environment variables only.
Please check https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#environment-variable-configuration

In case you want to add support of different DNS providers your contribution is 
highly apprectiated.

Wildcard certificates can not be issued with non-wildcard for the same domain.
I.e. it's not possible to issue certificates for `*.example.com` and
`www.example.com` at the same time.

## ACME v1

Still supported with flag `--acme-v1`.
Only HTTP challenge is supported at the moment.

## Installation

Please be informed that the quickiest and easiest way of installation is to use your OS
installation way because Python way includes compilation of dependencies that
may take much time and CPU resources and may require you to install all build
dependencies.

### Fastest way

Just download executable compiled with [pyinstaller](https://github.com/pyinstaller/pyinstaller).

```
wget https://github.com/kshcherban/acme-nginx/releases/download/v0.1.2/acme-nginx
chmod +x acme-nginx
```

### Python way

Automatically
```
pip install acme-nginx
```

or manually
```
git clone https://github.com/kshcherban/acme-nginx
cd acme-nginx
python setup.py install
```

### Docker way

You can build docker image with acme-nginx inside:

```
docker build -t acme-nginx .
docker run --rm -v /etc/nginx:/etc/nginx --pid=host \
	-d example.com -d www.example.com
```

There is also single binary in docker image compiled by `pyinstaller` , you can copy it like this:

```
docker run --name acme acme-nginx
docker cp acme:/usr/bin/acme-runner acme-nginx
docker rm acme
```



### Debian/Ubuntu way

```
sudo apt-get install -y python-openssl python-crypto python-setuptools
sudo python setup.py install
```

### CentOS/RedHat/Fedora way

```
sudo yum install -y pyOpenSSL python-crypto python-setuptools
sudo yum groupinstall -y "Development tools"
sudo python setup.py install
```

## Usage

Simplest scenario: you have neither letsencrypt [account key](https://letsencrypt.org/docs/account-id/) nor domain key and want to generate
certificate for example.com and www.example.com

```
sudo acme-nginx -d example.com -d www.example.com
```

You will see output similar to this:
```
Oct 12 23:42:17 Can not open key /etc/ssl/private/letsencrypt-account.key, generating new
Oct 12 23:42:17 Can not open key /etc/ssl/private/letsencrypt-domain.key, generating new
Oct 12 23:42:17 Trying to register account key
Oct 12 23:42:18 Registered!
Oct 12 23:42:18 Requesting challenge
Oct 12 23:42:19 Adding nginx virtual host and completing challenge
Oct 12 23:42:19 Creating file /etc/nginx/sites-enabled/letsencrypt
Oct 12 23:42:21 example.com verified!
Oct 12 23:42:21 Requesting challenge
Oct 12 23:42:21 Adding nginx virtual host and completing challenge
Oct 12 23:42:21 Creating file /etc/nginx/sites-enabled/letsencrypt
Oct 12 23:42:23 www.example.com verified!
Oct 12 23:42:23 Signing certificate
Oct 12 23:42:23 Certificate signed!
Oct 12 23:42:23 Writing result file in /etc/ssl/private/letsencrypt-domain.pem
Oct 12 23:42:23 Removing /etc/nginx/sites-enabled/letsencrypt and sending HUP to nginx
```

Certificate was generated into `/etc/ssl/private/letsencrypt-domain.pem`

You can now configure nginx to use it:
```
server {
  listen 443;
  ssl on;
  ssl_certificate /etc/ssl/private/letsencrypt-domain.pem;
  ssl_certificate_key /etc/ssl/private/letsencrypt-domain.key;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ...
```

To renew it simply rerun the command! You can put it in cron, but don't forget
about letsencrypt [rate limits](https://letsencrypt.org/docs/rate-limits/).

More complicated scenario: you have both account, domain keys and custom virtual host
```
sudo acme-nginx \
    -k /path/to/account.key \
    --domain-private-key /path/to/domain.key \
    --virtual-host /etc/nginx/sites-enabled/customvhost \
    -o /path/to/signed_certificate.pem \
    -d example.com -d www.example.com
```

### Wildcard certificates

For wildcard certificate you need to have your domain managed by DNS provider
with API. Currently only [DigitalOcean DNS](https://www.digitalocean.com/docs/networking/dns/) and
[AWS Route53](https://aws.amazon.com/route53/) are supported.

Example how to get wildcard certificate without nginx
```
sudo acme-nginx --no-reload-nginx --dns-provider route53 -d "*.example.com"
```

#### DigitalOcean

Please create and export your DO API token as `API_TOKEN` env variable.
Now you can generate wildcard certificate
```
sudo su -
export API_TOKEN=yourDigitalOceanApiToken
acme-nginx --dns-provider digitalocean -d '*.example.com'
```

### Debug

To debug please use `--debug` flag. With debug enabled all intermediate files
will not be removed, so you can check `/etc/nginx/sites-enabled` for temporary
virtual host configuration, by default it's `/etc/nginx/sites-enabled/0-letsencrypt.conf`.

Execute `acme-nginx --help` to see all available flags and their default values.

### Renewal

Personally i use following cronjob to renew certificates of my blog. Here's contents
of `/etc/cron.d/renew-cert`

```
MAILTO=insider@prolinux.org
12 11 10 * * root timeout -k 600 -s 9 3600 /usr/local/bin/acme-nginx -d prolinux.org -d www.prolinux.org >> /var/log/letsencrypt.log 2>&1 || echo "Failed to renew certificate"
```
