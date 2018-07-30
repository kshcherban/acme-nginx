import Crypto.PublicKey.RSA
import OpenSSL
import base64
import binascii
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2


__version__ = "0.1.3"


class Acme(object):
    def __init__(
            self,
            api_url,
            logger,
            domains=None,
            vhost='/etc/nginx/sites-enabled/0-letsencrypt.conf',
            account_key='/etc/ssl/private/letsencrypt-account.key',
            domain_key='/etc/ssl/private/letsencrypt-domain.key',
            cert_path='/etc/ssl/private/letsencrypt-domain.pem',
            dns_provider=None,
            debug=False):
        """
        Params:
            api_url, str, Letsencrypt API URL
            logger, logging object
            debug, bool, if debug mode enabled
            domains, list, list with domain names for certificate
            vhost, str, path to nginx virtual host config
            account_key, str, path to letsencrypt account key
            domain_key, str, path to certificate private key
            cert_path, str, path to output certificate file
            dns_provider, list, dns provider that is used for dns challenge
        """
        self.debug = debug
        if not domains:
            domains = list()
        self.domains = domains
        self.vhost = vhost
        self.account_key = account_key
        self.domain_key = domain_key
        self.cert_path = cert_path
        self.api_url = api_url
        self.log = logger
        # LetsEncrypt Root CA certificate chain, needed for ACMEv1
        self.chain = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"
        self.dns_provider = dns_provider

    def _reload_nginx(self):
        """ Return nginx master process id and sends HUP to it """
        try:
            m_pid = max(map(int, subprocess.Popen(
                'ps -o ppid= -C nginx'.split(),
                stdout=subprocess.PIPE).communicate()[0].split()))
            self.log.info('killing nginx process {0} with HUP'.format(m_pid))
            os.kill(m_pid, 1)
        except ValueError:
            self.log.error('no nginx process found, please make sure nginx is running')
            raise
        return m_pid

    def _write_vhost(self):
        """ Write virtual host configuration for http """
        challenge_file = tempfile.mkdtemp()
        self.log.info('created challenge file into {0}'.format(challenge_file))
        os.chmod(challenge_file, 0o777)
        vhost_data = """
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    location /.well-known/acme-challenge/ {{
        alias {alias}/;
        try_files $uri =404;
    }}
}}""".format(domain=' '.join(self.domains), alias=challenge_file)
        self.log.info('writing virtual host into {0}'.format(self.vhost))
        with open(self.vhost, 'w') as fd:
            fd.write(vhost_data)
        os.chmod(self.vhost, 0o644)
        self._reload_nginx()
        return challenge_file

    def _write_challenge(self, challenge_dir, token, thumbprint):
        self.log.info('writing challenge file into {0}'.format(self.vhost))
        with open('{0}/{1}'.format(challenge_dir, token), 'w') as fd:
            fd.write("{0}.{1}".format(token, thumbprint))

    def create_key(self, key_path, key_type=OpenSSL.crypto.TYPE_RSA, bits=2048):
        """
        Return created private key and writes it into key_path
        Params:
            key_path, str, writable path for key
            key_type, int, SSL key type
            bits, int, the number of bits of the key
        Return:
            string with private key
        """
        try:
            with open(key_path, 'r') as fd:
                private_key = fd.read()
        except IOError:
            key = OpenSSL.crypto.PKey()
            key.generate_key(key_type, bits)
            private_key = OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key)
            self.log.info('can not open key, writing new in {path}'.format(path=key_path))
            if not os.path.isdir(os.path.dirname(key_path)):
                os.mkdir(os.path.dirname(key_path))
            with open(key_path, 'wb') as fd:
                fd.write(private_key)
            os.chmod(key_path, 0o400)
        return private_key

    def create_csr(self):
        """ Generate CSR
        Return:
            string with CSR in DER format
        """
        sna = ', '.join(['DNS:{0}'.format(i) for i in self.domains]).encode('utf8')
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = self.domains[0]
        req.add_extensions([OpenSSL.crypto.X509Extension(
            'subjectAltName'.encode('utf8'), critical=False, value=sna)])
        with open(self.domain_key, 'r') as fd:
            key = fd.read()
        pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        req.set_pubkey(pk)
        req.set_version(2)
        req.sign(pk, "sha256")
        return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, req)

    @staticmethod
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    def _sign_message(self, message):
        """
        Sign provided message with key
        Params:
            message, str, message to sign
        Return:
            string with signed message
        """
        with open(self.account_key, 'r') as fd:
            key = fd.read()
        pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        return OpenSSL.crypto.sign(pk, message.encode('utf8'), "sha256")

    def _jws(self):
        """ Return JWS dict from string account key """
        with open(self.account_key, 'r') as fd:
            key = fd.read()
        pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        pk_asn1 = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pk)
        k = Crypto.PublicKey.RSA.importKey(pk_asn1)
        # private key public exponent in hex format
        exponent = "{0:x}".format(k.e)
        exponent = "0{0}".format(exponent) if len(exponent) % 2 else exponent
        # private key modulus in hex format
        modulus = "{0:x}".format(k.n)
        header = {
            "alg": "RS256",
            "jwk": {
                "e": self._b64(binascii.unhexlify(exponent.encode('utf8'))),
                "kty": "RSA",
                "n": self._b64(binascii.unhexlify(modulus.encode('utf8')))}}
        return header

    def _thumbprint(self):
        """ Return account thumbprint """
        accountkey_json = json.dumps(
            self._jws()['jwk'],
            sort_keys=True,
            separators=(',', ':'))
        return self._b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    def _cleanup(self, files):
        if not self.debug:
            for f in files:
                self.log.info('removing {0}'.format(f))
                try:
                    if os.path.isdir(f):
                        os.rmdir(f)
                    else:
                        os.remove(f)
                except OSError:
                    self.log.debug('{0} does not exist'.format(f))

    def _send_signed_request(self, url, payload=None, directory=None):
        """
        Send signed request to ACME CA
        Params:
            url, str, url for request
            payload, any type, any payload you want to send, usually dict
            directory, dict, directory data from acme server
        """
        if not payload:
            payload = {}
        request_headers = {
            "Content-Type": "application/jose+json",
            "User-Agent": "acme-nginx/{0} urllib".format(self.version())
        }
        payload64 = self._b64(json.dumps(payload).encode('utf8'))
        # If not set then ACMEv1 is used
        if directory:
            # jwk and kid header fields are mutually exclusive
            if directory['_kid']:
                protected = {'kid': directory['_kid']}
            else:
                protected = self._jws()
            protected["nonce"] = urlopen(Request(
                directory['newNonce'],
                headers=request_headers)
            ).headers['Replay-Nonce']
            protected["url"] = url
            protected["alg"] = "RS256"  # set for compatibility
        else:
            protected = self._jws()
            protected["nonce"] = urlopen(self.api_url + "/directory").headers['Replay-Nonce']
        protected64 = self._b64(json.dumps(protected).encode('utf8'))
        signature = self._sign_message("{0}.{1}".format(protected64, payload64))
        data = json.dumps({
            "protected": protected64,
            "payload": payload64,
            "signature": self._b64(signature)})
        try:
            resp = urlopen(Request(url, data=data.encode('utf8'), headers=request_headers))
            resp_data = resp.read()
            try:
                resp_data = resp_data.decode('utf8')
            except UnicodeDecodeError:
                pass
            return resp.getcode(), resp_data, resp.headers
        except Exception as e:
            return getattr(e, "code", None), \
                   getattr(e, "read", e.__str__)(), \
                   getattr(e, "headers", None)

    def _verify_challenge(self, url, domain):
        """ Verify challenge for domain """
        self.log.info('waiting for {0} challenge verification'.format(domain))
        checks_count = 60
        while True:
            checks_count -= 1
            if checks_count <= 0:
                self.log.error('reached waiting limit')
                sys.exit(1)
            challenge_status = json.loads(urlopen(url).read().decode('utf8'))
            if challenge_status['status'] == "pending":
                time.sleep(5)
                continue
            elif challenge_status['status'] == "valid":
                self.log.info('{0} verified!'.format(domain))
                break
            self.log.error('{0} challenge did not pass: {1}'.format(domain, challenge_status))
            sys.exit(1)

    @staticmethod
    def _get_challenge(challenges, challenge_type):
        """
        Return challenge from dict
        Params:
            challenge, dict, challenge data structure from acme api
            challenge_type, str, challenge type
        Return:
            challenge key
        """
        for challenge in challenges:
            if challenge['type'] == challenge_type:
                return challenge

    @staticmethod
    def version():
        return __version__
