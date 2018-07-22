import hashlib
import json
import re
import sys
import time
try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2
from Acme import Acme


class AcmeV2(Acme):
    def __init__(self, dns_provider=None, *args, **kwargs):
        """
        Params:
            dns_provider, list, dns provider that is used for dns challenge
        """
        self.dns_provider = dns_provider
        super(AcmeV2, self).__init__(*args, **kwargs)

    def register_account(self):
        """
        Generate new 2049 bit account key, domain key if not generated
        Register account key with ACME
        Returns:
             dict, directory data from acme server
        """
        try:
            self.log.info('trying to create account key {0}'.format(self.account_key))
            self.create_key(self.account_key)
        except Exception as e:
            self.log.error('creating key {0} {1}'.format(type(e).__name__, e))
            sys.exit(1)
        directory = urlopen(Request(
            self.api_url,
            headers={"Content-Type": "application/jose+json"})
        ).read().decode("utf8")
        # That is needed later for order placement
        directory = json.loads(directory)
        directory['_kid'] = None
        self.log.info('trying to register acmev2 account')
        code, result, headers = self.send_signed_request(
            directory['newAccount'],
            {"termsOfServiceAgreed": True},
            directory)
        if code == 201:
            self.log.info('registered!')
        elif code == 200:
            self.log.info('already registered')
        else:
            self.log.error('error registering: {0} {1} {2}'.format(code, result, headers))
            sys.exit(1)
        directory['_kid'] = headers['Location']
        try:
            self.log.info('trying to create domain key')
            self.create_key(self.domain_key)
        except Exception as e:
            self.log.error('creating key {0} {1}'.format(type(e).__name__, e))
            sys.exit(1)
        return directory

    def solve_http_challenge(self, directory):
        """
        Solve HTTP challenge
        Params:
            directory, dict, directory data from acme server
        """
        self.log.info('acmev2 http challenge')
        self.log.info('preparing new order')
        order_payload = {
            "identifiers": [{"type": "dns", "value": d} for d in self.domains]
        }
        code, order, order_headers = self.send_signed_request(
            directory['newOrder'], order_payload, directory)
        order = json.loads(order.decode("utf8"))
        self.log.info('order created')
        for url in order['authorizations']:
            auth = json.loads(urlopen(url).read().decode("utf8"))
            if self.debug:
                self.log.debug(json.dumps(auth))
            domain = auth['identifier']['value']
            self.log.info('verifying domain {0}'.format(domain))
            challenge = [c for c in auth['challenges'] if c['type'] == "http-01"][0]
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
            accountkey_json = json.dumps(
                self._jws()['jwk'],
                sort_keys=True,
                separators=(',', ':'))
            thumbprint = self._b64(
                hashlib.sha256(accountkey_json.encode('utf8')).digest())
            self.log.info('adding nginx virtual host and completing challenge')
            try:
                challenge_dir = self.write_vhost()
                self.write_challenge(challenge_dir, token, thumbprint)
            except Exception as e:
                self.log.error('error adding virtual host {0} {1}'.format(type(e).__name__, e))
                sys.exit(1)
            code, result, headers = self.send_signed_request(challenge['url'], {}, directory)
            if code > 399:
                self.log.error("error triggering challenge: {0} {1}".format(code, result))
                self._cleanup(
                    ['{0}/{1}'.format(challenge_dir, token), self.vhost],
                    directory=challenge_dir,
                    exit_with_error=True
                )
            self.log.info('waiting for challenge verification')
            while True:
                try:
                    challenge_status = json.loads(urlopen(url).read().decode('utf8'))
                except IOError as e:
                    self.log.error("error checking challenge: {0} {1}".format(
                        e.code, json.loads(e.read().decode('utf8'))))
                    self._cleanup(
                        ['{0}/{1}'.format(challenge_dir, token), self.vhost],
                        directory=challenge_dir,
                        exit_with_error=True
                    )
                if challenge_status['status'] == "pending":
                    time.sleep(2)
                elif challenge_status['status'] == "valid":
                    self.log.info('{0} verified!'.format(domain))
                    break
                else:
                    self.log.error('{0} challenge did not pass: {1}'.format(domain, challenge_status))
            self._cleanup(
                ['{0}/{1}'.format(challenge_dir, token)],
                directory=challenge_dir
            )
            self.log.info('signing certificate')
            csr = self.create_csr()
            code, result, headers = self.send_signed_request(
                order['finalize'], {"csr": self._b64(csr)}, directory)
            if self.debug:
                self.log.debug('{0}, {1}, {2}'.format(code, result, headers))
            if code > 399:
                self.log("error signing certificate: {0} {1}".format(code, result))
                self._cleanup(
                    ['{0}/{1}'.format(challenge_dir, token), self.vhost],
                    directory=challenge_dir,
                    exit_with_error=True
                )
            self.log.info('certificate signed!')
            self.log.info('downloading certificate')
            certificate_pem = urlopen(json.loads(result)['certificate']).read()
            self.log.info('writing result file in {0}'.format(self.cert_path))
            try:
                with open(self.cert_path, 'w') as fd:
                    fd.write(certificate_pem)
            except Exception as e:
                self.log.error('error writing cert: {0} {1}'.format(type(e).__name__, e))
            self._cleanup([self.vhost])
            self._reload_nginx()

    def get_certificate(self):
        directory = self.register_account()
        if self.dns_provider:
            self.log.warning('not implemented')
        else:
            self.solve_http_challenge(directory)
