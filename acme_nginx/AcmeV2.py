import hashlib
import json
import re
import sys
import time

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2
from .Acme import Acme
from .DigitalOcean import DigitalOcean

from .AWSRoute53 import AWSRoute53
from .Cloudflare import Cloudflare


class AcmeV2(Acme):
    def register_account(self):
        """
        Generate new 2049 bit account key, domain key if not generated
        Register account key with ACME
        Return:
             dict, directory data from acme server
        """
        try:
            self.log.info("trying to create account key {0}".format(self.account_key))
            self.create_key(self.account_key)
        except Exception as e:
            self.log.error("creating key {0} {1}".format(type(e).__name__, e))
            sys.exit(1)
        # directory is needed later for order placement
        directory = (
            urlopen(
                Request(self.api_url, headers={"Content-Type": "application/jose+json"})
            )
            .read()
            .decode("utf8")
        )
        directory = json.loads(directory)
        directory["_kid"] = None
        self.log.info("trying to register acmev2 account")
        payload = {"termsOfServiceAgreed": True}
        code, result, headers = self._send_signed_request(
            url=directory["newAccount"], payload=payload, directory=directory
        )
        if code == 201:
            self.log.info("registered!")
        elif code == 200:
            self.log.info("already registered")
        else:
            self.log.error(
                "error registering: {0} {1} {2}".format(code, result, headers)
            )
            sys.exit(1)
        directory["_kid"] = headers["Location"]
        try:
            self.log.info("trying to create domain key")
            self.create_key(self.domain_key)
        except Exception as e:
            self.log.error("creating key {0} {1}".format(type(e).__name__, e))
            sys.exit(1)
        return directory

    # helper function - poll until order status is valid
    def _poll_until_not(
        self, url, payload, directory, pending_statuses=["pending", "processing"]
    ):
        result, t0 = None, time.time()
        while (
            result is None
            or result["status"] in pending_statuses
            # or result.get("certificate") is None
        ):
            assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if result is None else 2)
            _, raw_result, _ = self._send_signed_request(url, payload, directory)
            result = json.loads(raw_result)
        return result

    def _sign_certificate(self, order, directory):
        """Sign certificate"""
        self.log.info("signing certificate")
        csr = self.create_csr()
        payload = {"csr": self._b64(csr)}
        code, finalize_result, headers = self._send_signed_request(
            url=order["finalize"], payload=payload, directory=directory
        )
        self.log.debug("{0}, {1}, {2}".format(code, finalize_result, headers))
        if code > 399:
            self.log.error(
                "error signing certificate: {0} {1}".format(code, finalize_result)
            )
            if not self.skip_nginx_reload:
                self._reload_nginx()
            sys.exit(1)
        self.log.info("certificate signed!")
        # applies to staging only atm
        self.log.info("waiting for certificate to be ready")
        result = self._poll_until_not(headers["Location"], "", directory)
        self.log.info("downloading certificate")
        certificate_url = result["certificate"]
        certificate_pem = self._send_signed_request(certificate_url, "", directory)[1]
        self.log.info("writing result file in {0}".format(self.cert_path))
        try:
            with open(self.cert_path, "w") as fd:
                fd.write(certificate_pem)
        except Exception as e:
            self.log.error("error writing cert: {0} {1}".format(type(e).__name__, e))
        if not self.skip_nginx_reload:
            self._reload_nginx()

    def solve_http_challenge(self, directory):
        """
        Solve HTTP challenge
        Params:
            directory, dict, directory data from acme server
        """
        self.log.info("acmev2 http challenge")
        self.log.info("preparing new order")
        order_payload = {
            "identifiers": [{"type": "dns", "value": d} for d in self.domains]
        }
        code, order, _ = self._send_signed_request(
            url=directory["newOrder"], payload=order_payload, directory=directory
        )
        self.log.debug(order)
        order = json.loads(order)
        if code >= 400:
            self.log.error("failed to create order")
            self.log.error(json.dumps(order))
            sys.exit(1)
        self.log.info("order created")
        for url in order["authorizations"]:
            order_data = self._send_signed_request(url, "", directory)
            auth = json.loads(order_data[1])
            self.log.debug(json.dumps(auth))
            domain = auth["identifier"]["value"]
            self.log.info("verifying domain {0}".format(domain))
            challenge = self._get_challenge(auth["challenges"], "http-01")
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
            thumbprint = self._thumbprint()
            self.log.info("adding nginx virtual host and completing challenge")
            try:
                challenge_dir = self._write_vhost()
                print(challenge_dir, token, thumbprint)
                self._write_challenge(challenge_dir, token, thumbprint)
            except Exception as e:
                self.log.error(
                    "error adding virtual host {0} {1}".format(type(e).__name__, e)
                )
                sys.exit(1)
            self.log.info("asking acme server to verify challenge")
            code, result, _ = self._send_signed_request(
                url=challenge["url"], directory=directory
            )
            try:
                if code > 399:
                    self.log.error(
                        "error triggering challenge: {0} {1}".format(code, result)
                    )
                    sys.exit(1)
                self._verify_challenge(url, domain, directory)
            finally:
                self._cleanup(
                    ["{0}/{1}".format(challenge_dir, token), self.vhost, challenge_dir]
                )
                if not self.skip_nginx_reload:
                    self._reload_nginx()
        self._sign_certificate(order, directory)

    def solve_dns_challenge(self, directory, client):
        """
        Solve DNS challenge
        Params:
            directory, dict, directory data from acme server
            client, object, dns provider client implementation
        """
        # no need to reload nginx for DNS challenge
        self.skip_nginx_reload = True
        self.log.info("acmev2 dns challenge")
        self.log.info("preparing new order")
        order_payload = {
            "identifiers": [{"type": "dns", "value": d} for d in self.domains]
        }
        code, order, _ = self._send_signed_request(
            url=directory["newOrder"], payload=order_payload, directory=directory
        )
        self.log.debug(order)
        order = json.loads(order)
        self.log.info("order created")
        for url in order["authorizations"]:
            order_data = self._send_signed_request(url, "", directory)
            auth = json.loads(order_data[1])
            self.log.debug(json.dumps(auth))
            domain = auth["identifier"]["value"]
            self.log.info("verifying domain {0}".format(domain))
            challenge = self._get_challenge(auth["challenges"], "dns-01")
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
            thumbprint = self._thumbprint()
            keyauthorization = "{0}.{1}".format(token, thumbprint)
            txt_record = self._b64(
                hashlib.sha256(keyauthorization.encode("utf8")).digest()
            )
            self.log.info(
                "creating TXT dns record _acme-challenge.{0} IN TXT {1}".format(
                    domain, txt_record
                )
            )
            try:
                record = client.create_record(
                    domain=domain,
                    name="_acme-challenge.{0}.".format(domain.lstrip("*.").rstrip(".")),
                    data=txt_record,
                )
            except Exception as e:
                self.log.error("error creating dns record")
                self.log.error(e)
                sys.exit(1)
            try:
                self.log.info("asking acme server to verify challenge")
                payload = {"keyAuthorization": keyauthorization}
                code, result, headers = self._send_signed_request(
                    url=challenge["url"], payload=payload, directory=directory
                )
                if code > 399:
                    self.log.error(
                        "error triggering challenge: {0} {1}".format(code, result)
                    )
                    raise Exception(result)
                self._verify_challenge(url, domain, directory)
            finally:
                try:
                    if not self.debug:
                        self.log.info("delete dns record")
                        client.delete_record(domain=domain, record=record)
                except Exception as e:
                    self.log.error("error deleting dns record")
                    self.log.error(e)
        self._sign_certificate(order, directory)

    def get_certificate(self):
        directory = self.register_account()
        if self.dns_provider:
            if self.dns_provider == "digitalocean":
                dns_client = DigitalOcean()
            elif self.dns_provider == "route53":
                dns_client = AWSRoute53()
                pass
            elif self.dns_provider == "cloudflare":
                dns_client = Cloudflare()
            self.solve_dns_challenge(directory, dns_client)
        else:
            self.solve_http_challenge(directory)
