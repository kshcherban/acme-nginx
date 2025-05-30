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

* Simply works with running nginx or without it (DNS validation only)
* Can issue [wildcard certificates](https://en.wikipedia.org/wiki/Wildcard_certificate)!
* Easy to use and extend

## Description

This is [ACME](https://ietf-wg-acme.github.io/acme/) client implementation in
Python originally based on https://github.com/diafygi/acme-tiny code.
Now completely different.
It's written in pure Python depends on [cryptography](https://cryptography.io/en/latest/)
and the only binary it calls is **ps** to determine nginx master process id
to send `SIGHUP` to it during challenge completion.

As you may not trust this script feel free to check source code, it's small, under 1000 lines of code in total.

Script should be run as root on host with running nginx server if you use http verification or if you use DNS verification as a regular user.
Domain for which you request certificate should point to that host's IP and port
80 should be available from outside if you use HTTP challenge.
Script can generate all keys for you if you don't set them with command line arguments.
Keys are RSA with length of 2048 bytes.
You can specify as many alternative domain names as you wish.
The result PEM file is a **certificate chain** containing your signed
certificate and letsencrypt signed chain. You can use it with nginx.

Should work with Python >= 3.9.2

## ACME v2

ACME v2 is supported partially: only `http-01` and `dns-01` challenges.
Check https://tools.ietf.org/html/draft-ietf-acme-acme-07#section-9.7.6

`http-01` challenge is passed exactly as in v1 protocol realization.

`dns-01` currently supports following providers:

- DigitalOcean
- AWS Route53
- Cloudflare

Technically nginx is not needed for this type of challenge but script still calls nginx reload by default
because it assumes that you store certificates on the same server where you issue
them. To disable that behavior please specify `--no-reload-nginx` parameter.

AWS Route53 uses `default` profile in session, specifying profile works with environment variables only.
Please check https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#environment-variable-configuration

In case you want to add support of different DNS providers your contribution is 
highly appreciated.

Wildcard certificates can not be issued with non-wildcard for the same domain.
I.e. it's not possible to issue certificates for `*.example.com` and
`www.example.com` at the same time.

## ACME v1

Is deprecated and not supported by LetsEncrypt anymore, so it was removed from that project too.

## Installation

### Preferred way

Using [uv](https://github.com/astral-sh/uv). 

1. First [install](https://docs.astral.sh/uv/getting-started/installation/) uv:

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   
2. Clone acme-nginx:

   ```bash
   git clone https://github.com/kshcherban/acme-nginx
   ```

3. Install it:

   ```bash
   cd acme-nginx
   uv run acme-nginx
   ```

### Python pip way

Automatically
```
pip3 install acme-nginx
```

### Docker way

You can build docker image with acme-nginx inside:

```
docker build -t acme-nginx .
docker run --rm -v /etc/nginx:/etc/nginx --pid=host \
	-d example.com -d www.example.com
```



### Generate requirements

You can generate requirements.txt file with uv like: 
`uv export --no-hashes --no-emit-workspace > requirements.txt`

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
Oct 12 23:42:19 Creating file /etc/nginx/conf.d/0-letsencrypt.conf
Oct 12 23:42:21 example.com verified!
Oct 12 23:42:21 Requesting challenge
Oct 12 23:42:21 Adding nginx virtual host and completing challenge
Oct 12 23:42:21 Creating file /etc/nginx/conf.d/0-letsencrypt.conf
Oct 12 23:42:23 www.example.com verified!
Oct 12 23:42:23 Signing certificate
Oct 12 23:42:23 Certificate signed!
Oct 12 23:42:23 Writing result file in /etc/ssl/private/letsencrypt-domain.pem
Oct 12 23:42:23 Removing /etc/nginx/conf.d/0-letsencrypt.conf and sending HUP to nginx
```

Certificate was generated into `/etc/ssl/private/letsencrypt-domain.pem`

You can now configure nginx to use it:
```nginx
server {
  listen 443;
  ssl on;
  ssl_certificate /etc/ssl/private/letsencrypt-domain.pem;
  ssl_certificate_key /etc/ssl/private/letsencrypt-domain.key;
  ...
```

To renew it simply rerun the command! You can put it in cron, but don't forget
about letsencrypt [rate limits](https://letsencrypt.org/docs/rate-limits/).

More complicated scenario: you have both account, domain keys and custom virtual host
```
sudo acme-nginx \
    -k /path/to/account.key \
    --domain-private-key /path/to/domain.key \
    --virtual-host /etc/nginx/conf.d/customvhost \
    -o /path/to/signed_certificate.pem \
    -d example.com -d www.example.com
```

### Wildcard certificates

For wildcard certificate you need to have your domain managed by DNS provider
with API. Currently only [DigitalOcean DNS](https://www.digitalocean.com/docs/networking/dns/), [Cloudflare](https://cloudflare.com) and
[AWS Route53](https://aws.amazon.com/route53/) are supported.

Example how to get wildcard certificate without nginx
```
sudo acme-nginx --no-reload-nginx --dns-provider route53 -d "*.example.com"
```

#### DigitalOcean

Please create and export your DO API token as `API_TOKEN` env variable.
Now you can generate wildcard certificate

```bash
sudo su -
export API_TOKEN=yourDigitalOceanApiToken
acme-nginx --dns-provider digitalocean -d '*.example.com'
```

### Cloudflare

[Create API token](https://dash.cloudflare.com/profile/api-tokens) first. Then export it as `API_TOKEN` environment variable and use like this:

```bash
sudo su -
export API_TOKEN=yourCloudflareApiToken
acme-nginx --dns-provider cloudflare -d '*.example.com'
```



### Debug

To debug please use `--debug` flag. With debug enabled all intermediate files
will not be removed, so you can check `/etc/nginx/conf.d` for temporary
virtual host configuration, by default it's `/etc/nginx/conf.d/0-letsencrypt.conf`.

Execute `acme-nginx --help` to see all available flags and their default values.

### Renewal

Personally I used the following cronjob to renew certificates of my blog. Here's content
of `/etc/cron.d/renew-cert`

```
MAILTO=insider@prolinux.org
12 11 10 * * root timeout -k 600 -s 9 3600 /usr/local/bin/acme-nginx -d prolinux.org -d www.prolinux.org --renew-days 33 >> /var/log/letsencrypt.log 2>&1 || echo "Failed to renew certificate"
```
