# acme-nginx

## Description

This is [ACME](https://ietf-wg-acme.github.io/acme/) client implementation in
Python based on https://github.com/diafygi/acme-tiny code.
It's written in pure Python depends on pyOpenSSL and pycrypto
and the only binary it calls is **ps** to determine nginx master process id
to send SIGHUP to it during challenge completion.

As you may not trust this script feel free to check source code,
it's under 400 lines.

Script should be run as root on host with running nginx.
Domain for which you request certificate should point to that host's IP and port
80 should be available from outside.
Script can generate all keys for you if you don't set them in command line.
Keys are RSA with length of 2048 bytes.
You can specify as many alternative domain names as you wish.
The result PEM file is a **certificate chain** containing your signed
certificate and letsencrypt signed chain. You can use it with nginx.

Should work with Python >= 2.6

## Installation

Please be informed that the quickiest and easiest way of installation is to use your OS
installation way because Python way includes compilation of dependencies that
may take much time and CPU resources and may require you to install all build
dependencies.

### Python way

Automatically
```
pip3 install acme-nginx
```

or manually
```
git clone https://github.com/kshcherban/acme-nginx
cd acme-nginx
python setup.py install
```

### Debian/Ubuntu way

```
sudo apt-get install -y python-openssl python-crypto
sudo python setup.py install
```

### CentOS/RedHat/Fedora way

```
sudo yum install -y pyOpenSSL python-crypto
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

## Debug

To debug please use `--debug` flag. With debug enabled all intermediate files
will not be removed, so you can check `/etc/nginx/sites-enabled` for temporary
virtual host configuration, by default it's `/etc/nginx/sites-enabled/0-letsencrypt`.

Execute `acme-nginx --help` to see all available flags and their default values.

## Renewal

Personally i use following cronjob to renew certificates of my blog:

```
cat /etc/cron.d/renew-cert
MAILTO=insider@prolinux.org
12 11 10 * * root /usr/local/bin/acme-nginx -d prolinux.org -d www.prolinux.org >> /var/log/letsencrypt.log
```
