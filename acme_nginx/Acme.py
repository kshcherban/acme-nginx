import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from urllib.request import urlopen, Request


__version__ = "0.5.0"


class Acme(object):
    def __init__(
        self,
        api_url,
        logger,
        domains=None,
        vhost="/etc/nginx/conf.d/0-letsencrypt.conf",
        account_key="/etc/ssl/private/letsencrypt-account.key",
        domain_key="/etc/ssl/private/letsencrypt-domain.key",
        cert_path="/etc/ssl/private/letsencrypt-domain.pem",
        dns_provider=None,
        skip_nginx_reload=False,
        renew_days=None,
        debug=False,
    ):
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
            skip_nginx_reload, bool, should nginx be reloaded after certificate issue
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
        self.dns_provider = dns_provider
        self.skip_nginx_reload = skip_nginx_reload
        self.renew_days = renew_days

        self.IsOutOfDate = True
        if self.renew_days:
            try:
                with open(self.cert_path, "rb") as cert_file:
                    cert_data = cert_file.read()

                # Parse certificate using cryptography
                cert = x509.load_pem_x509_certificate(cert_data)
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc

                now = datetime.now(timezone.utc)
                certTimeThreshold = not_after - timedelta(days=self.renew_days)

                self.log.debug(
                    "x509: {0}, not_before: {1}, not_after: {2}".format(
                        cert, not_before, not_after
                    )
                )

                self.IsOutOfDate = (
                    (not_before > now) or (not_after < now) or (certTimeThreshold < now)
                )
                self.log.info(
                    "Cert file {1} (expiration time {0})".format(
                        certTimeThreshold,
                        "is out of date" if self.IsOutOfDate else "is not out of date",
                    )
                )

            except OSError as e:
                if e.errno == 2:
                    self.log.info(
                        "Cert file {0} not found -> DO UPDATE CERT".format(
                            self.cert_path
                        )
                    )
            except Exception as e:
                raise e

    def _reload_nginx(self):
        """Reload nginx"""
        self.log.info("running nginx -s reload")
        process = subprocess.Popen(
            "nginx -s reload".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        process_out = process.communicate()
        self.log.debug(process_out[0])
        self.log.debug(process_out[1])
        if process.returncode > 0:
            self.log.error("failed to reload nginx")
            self.log.error(process_out[1])

    def _write_vhost(self):
        """Write virtual host configuration for http"""
        challenge_file = tempfile.mkdtemp()
        self.log.info("created challenge file into {0}".format(challenge_file))
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
}}""".format(domain=" ".join(self.domains), alias=challenge_file)
        self.log.info("writing virtual host into {0}".format(self.vhost))
        with open(self.vhost, "w") as fd:
            fd.write(vhost_data)
        os.chmod(self.vhost, 0o644)
        if not self.skip_nginx_reload:
            self._reload_nginx()
        return challenge_file

    def _write_challenge(self, challenge_dir, token, thumbprint):
        self.log.info("writing challenge file into {0}".format(self.vhost))
        with open("{0}/{1}".format(challenge_dir, token), "w") as fd:
            fd.write("{0}.{1}".format(token, thumbprint))

    def create_key(self, key_path, key_type=2, bits=2048):  # TYPE_RSA = 2
        """
        Return created private key and writes it into key_path
        Params:
            key_path, str, writable path for key
            key_type, int, SSL key type (2 = RSA, 6 = EC) - using direct values instead of OpenSSL constants
            bits, int, the number of bits of the key
        Return:
            string with private key
        """
        try:
            with open(key_path, "r") as fd:
                private_key = fd.read()
        except IOError:
            # Generate a new key using cryptography
            if key_type == 2:  # RSA
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=bits,
                )
                private_key = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            else:
                raise ValueError(
                    f"Unsupported key type: {key_type}, only RSA is supported"
                )

            self.log.info(
                "can not open key, writing new in {path}".format(path=key_path)
            )
            if not os.path.isdir(os.path.dirname(key_path)):
                os.mkdir(os.path.dirname(key_path))
            with open(key_path, "wb") as fd:
                fd.write(private_key)
            os.chmod(key_path, 0o400)

        # Return string representation if it's in bytes
        if isinstance(private_key, bytes):
            return private_key.decode("utf-8")
        return private_key

    def create_csr(self):
        """Generate CSR
        Return:
            string with CSR in DER format
        """
        # Load the private key
        with open(self.domain_key, "r") as fd:
            key_pem = fd.read()

        private_key = serialization.load_pem_private_key(
            key_pem.encode() if isinstance(key_pem, str) else key_pem,
            password=None,
        )

        # Create a name object for the subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, self.domains[0]),
            ]
        )

        # Create the alternative names extension
        alt_names = [x509.DNSName(domain) for domain in self.domains]
        san = x509.SubjectAlternativeName(alt_names)

        # Create CSR builder
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(san, critical=False)

        # Sign the CSR with the private key
        csr = builder.sign(private_key, hashes.SHA256())

        # Return the CSR in DER format
        return csr.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def _b64(b):
        """
        Helper function base64 encode for jose spec
        """
        if isinstance(b, str):
            b = b.encode("utf8")
        return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

    def _sign_message(self, message):
        """
        Sign provided message with key
        Params:
            message, str, message to sign
        Return:
            string with signed message
        """
        with open(self.account_key, "r") as fd:
            key_pem = fd.read()

        # Load the key with cryptography
        priv_key = serialization.load_pem_private_key(
            key_pem.encode() if isinstance(key_pem, str) else key_pem,
            password=None,
        )

        # Sign the message with proper padding and hashing
        if isinstance(priv_key, rsa.RSAPrivateKey):
            signature = priv_key.sign(
                message.encode("utf8"), padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            # For other key types, fall back to a generic approach
            raise ValueError("Unsupported key type, only RSA is currently supported")

        return signature

    def _jws(self):
        """Return JWS dict from string account key"""
        with open(self.account_key, "r") as fd:
            key_pem = fd.read()

        # Load the key with cryptography
        priv_key = serialization.load_pem_private_key(
            key_pem.encode() if isinstance(key_pem, str) else key_pem,
            password=None,
        )

        if isinstance(priv_key, rsa.RSAPrivateKey):
            # Get the public numbers from the private key
            public_numbers = priv_key.public_key().public_numbers()

            # Convert e and n to base64url format
            e_bytes = public_numbers.e.to_bytes(
                (public_numbers.e.bit_length() + 7) // 8, byteorder="big"
            )
            n_bytes = public_numbers.n.to_bytes(
                (public_numbers.n.bit_length() + 7) // 8, byteorder="big"
            )

            header = {
                "alg": "RS256",
                "jwk": {
                    "e": self._b64(e_bytes),
                    "kty": "RSA",
                    "n": self._b64(n_bytes),
                },
            }
            return header
        else:
            raise ValueError("Unsupported key type, only RSA is currently supported")

    def _thumbprint(self):
        """Return account thumbprint"""
        accountkey_json = json.dumps(
            self._jws()["jwk"], sort_keys=True, separators=(",", ":")
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(accountkey_json.encode("utf8"))
        return self._b64(digest.finalize())

    def _cleanup(self, files):
        if not self.debug:
            for f in files:
                self.log.info("removing {0}".format(f))
                try:
                    if os.path.isdir(f):
                        os.rmdir(f)
                    else:
                        os.remove(f)
                except OSError:
                    self.log.debug("{0} does not exist".format(f))

    def _send_signed_request(self, url, payload=None, directory=None):
        """
        Send signed request to ACME CA
        Params:
            url, str, url for request
            payload, any type, any payload you want to send, usually dict
            directory, dict, directory data from acme server
        """
        request_headers = {
            "Content-Type": "application/jose+json",
            "User-Agent": "acme-nginx/{0} urllib".format(self.version()),
        }
        if payload is None:
            payload = {}
        # on POST-as-GET, final payload has to be just empty string
        if payload == "":
            payload64 = ""
        else:
            payload64 = self._b64(json.dumps(payload).encode("utf8"))
        if directory:
            # jwk and kid header fields are mutually exclusive
            if directory["_kid"]:
                protected = {"kid": directory["_kid"]}
            else:
                protected = self._jws()
            protected["nonce"] = urlopen(
                Request(directory["newNonce"], headers=request_headers)
            ).headers["Replay-Nonce"]
            protected["url"] = url
            protected["alg"] = "RS256"  # set for compatibility
        protected64 = self._b64(json.dumps(protected).encode("utf8"))
        signature = self._sign_message("{0}.{1}".format(protected64, payload64))
        data = json.dumps(
            {
                "protected": protected64,
                "payload": payload64,
                "signature": self._b64(signature),
            }
        )
        try:
            resp = urlopen(
                Request(
                    url,
                    data=data.encode("utf8"),
                    headers=request_headers,
                    method="POST",
                )
            )
            resp_data = resp.read()
            try:
                resp_data = resp_data.decode("utf8")
            except UnicodeDecodeError:
                pass
            return resp.getcode(), resp_data, resp.headers
        except Exception as e:
            return (
                getattr(e, "code", None),
                getattr(e, "read", e.__str__)(),
                getattr(e, "headers", None),
            )

    def _verify_challenge(self, url, domain, directory=None):
        """Verify challenge for domain"""
        self.log.info("waiting for {0} challenge verification".format(domain))
        checks_count = 60
        while True:
            checks_count -= 1
            if checks_count <= 0:
                self.log.error("reached waiting limit")
                sys.exit(1)
            challenge_status = json.loads(
                self._send_signed_request(url, "", directory)[1]
            )
            if challenge_status["status"] == "pending":
                time.sleep(5)
                continue
            elif challenge_status["status"] == "valid":
                self.log.info("{0} verified!".format(domain))
                break
            self.log.error(
                "{0} challenge did not pass: {1}".format(domain, challenge_status)
            )
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
            if challenge["type"] == challenge_type:
                return challenge

    @staticmethod
    def version():
        return __version__
