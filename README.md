# letsencrypt-nginx

## Description

This is [ACME](https://ietf-wg-acme.github.io/acme/) client implementation in
Python based on https://github.com/diafygi/acme-tiny code.
It's written in pure Python depends on pyOpenSSL and pycrypto
and the only binary it calls is **pidof** to determine nginx master process id
to send SIGHUP to it during challenge completion.

As you may not trust this script feel free to check source code,
it's under 350 lines.

Script should be run as root on host with running nginx.
Domain for which you request certificate should point to that host's IP and port
80 should be available from outside.
Script can generate all keys for you if you don't set them in command line.
Keys are RSA with length of 2048 bytes.
You can specify as many alternative domain names as you wish.
The result PEM file is a **certificate chain** containing your signed
certificate and letsencrypt signed chain. You can use it with nginx.

## Installation

```
python setup.py install
```

## Usage

Simplest scenario: you have neither letsencrypt [account key](https://letsencrypt.org/docs/account-id/) nor domain key and want to generate
certificate for example.com and www.example.com

```
sudo letsencrypt-nginx -d example.com -d www.example.com
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
sudo letsencrypt-nginx \
    -k /path/to/account.key \
    --domain-private-key /path/to/domain.key \
    --virtual-host /etc/nginx/sites-enabled/customvhost \
    -o /path/to/signed_certificate.pem \
    -d example.com -d www.example.com
```
