import base64
import json
import re
import sys
import textwrap
try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2
from .Acme import Acme


class AcmeV1(Acme):
    def register_account(self):
        """
        Generate new 2049 bit account key, domain key if not generated
        Register account key with ACME
        Return:
             dict, directory data from acme server
        """
        try:
            self.log.info('trying to create account key {0}'.format(self.account_key))
            account_key = self.create_key(self.account_key)
        except Exception as e:
            self.log.error('creating key {0} {1}'.format(type(e).__name__, e))
            sys.exit(1)
        self.log.info('trying to register acmev1 account')
        payload = {
            "resource": "new-reg",
            "agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf"
        }
        code, result, headers = self._send_signed_request(url=self.api_url + "/acme/new-reg", payload=payload)
        if code == 201:
            self.log.info('registered!')
        elif code == 409:
            self.log.info('already registered')
        else:
            self.log.error('error registering: {0} {1} {2}'.format(code, result, headers))
            sys.exit(1)
        return account_key

    def get_certificate(self):
        # Generate new 2048 bit account, domain private keys only if not set
        self.register_account()
        try:
            self.create_key(self.domain_key)
        except Exception as e:
            self.log.error('creating key {0} {1}'.format(type(e).__name__, e))
            sys.exit(1)
        csr = self.create_csr()
        # Solve challenge
        self.log.info('acmev1 http challenge')
        for domain in self.domains:
            self.log.info('requesting challenge for {0}'.format(domain))
            payload = {
                "resource": "new-authz",
                "identifier": {"type": "dns", "value": domain},
            }
            code, result, _ = self._send_signed_request(url=self.api_url + "/acme/new-authz", payload=payload)
            if code != 201:
                self.log.error('error requesting challenges: {0} {1}'.format(code, result))
                sys.exit(1)
            challenge = self._get_challenge(json.loads(result)['challenges'], "http-01")
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
            thumbprint = self._thumbprint()
            self.log.info('adding nginx virtual host and completing challenge')
            try:
                challenge_dir = self._write_vhost()
                self._write_challenge(challenge_dir, token, thumbprint)
            except Exception as e:
                self.log.error('error adding virtual host {0} {1}'.format(type(e).__name__, e))
                sys.exit(1)
            self.log.info('asking acme server to verify challenge for {0}'.format(domain))
            try:
                payload = {
                    "resource": "challenge",
                    "keyAuthorization": "{0}.{1}".format(token, thumbprint),
                }
                code, result, _ = self._send_signed_request(url=challenge['uri'], payload=payload)
                if code != 202:
                    self.log.error("error triggering challenge: {0} {1}".format(code, result))
                    sys.exit(1)
                self._verify_challenge(challenge['uri'], domain)
            finally:
                self._cleanup(['{0}/{1}'.format(challenge_dir, token), self.vhost, challenge_dir])
                self._reload_nginx()
        self.log.info('signing certificate')
        try:
            payload = {"resource": "new-cert", "csr": self._b64(csr)}
            code, result, _ = self._send_signed_request(url=self.api_url + "/acme/new-cert", payload=payload)
            if code != 201:
                self.log.error("error signing certificate: {0} {1}".format(code, result))
                sys.exit(1)
            self.log.info('certificate signed!')
            try:
                self.log.info('getting chain from {0}'.format(self.chain))
                chain_str = urlopen(self.chain).read()
                if chain_str:
                    chain_str = chain_str.decode('utf8')
            except Exception as e:
                self.log.error('error getting chain: {0} {1}'.format(type(e).__name__, e))
                sys.exit(1)
            self.log.info('writing result file in {0}'.format(self.cert_path))
            try:
                with open(self.cert_path, 'w') as fd:
                    fd.write(
                        '''-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'''.format(
                            '\n'.join(textwrap.wrap(
                                base64.b64encode(result).decode('utf8'),
                                64
                            )))
                    )
                    fd.write(chain_str)
            except Exception as e:
                self.log.error('error writing cert: {0} {1}'.format(type(e).__name__, e))
                sys.exit(1)
        finally:
            self._reload_nginx()
