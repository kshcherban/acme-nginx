import argparse
import OpenSSL
import Crypto.PublicKey.RSA
import base64
import binascii
import json
import re
import hashlib
import os
import tempfile
import time
import textwrap
import sys
import subprocess
try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2


CA = "https://acme-v01.api.letsencrypt.org"
#CA = "https://acme-staging.api.letsencrypt.org"
TOS = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"
CHAIN = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"


def reload_nginx():
    """ Returns nginx master process id and sends HUP to it """
    m_pid = max(map(int, subprocess.Popen(
        'ps -o ppid= -C nginx'.split(),
        stdout=subprocess.PIPE).communicate()[0].split()))
    os.kill(m_pid, 1)
    return m_pid


def nginx_challenge(domain, token, thumbprint, vhost_conf):
    """
    Creates nginx virtual host for challenge solve
    Params:
        domain, str, server name
        token, str, token file name for challenge
        thumbprint, str, JWK Thumbprint
        vhost_conf, str, path to virtual host configuration
    Returns:
        tuple of
        int nginx master pid
        string name of temporary directory for challenge
    """
    alias = tempfile.mkdtemp()
    os.chmod(alias, 0o777)
    vhost = """
server {{
    listen 80;
    server_name {domain};
    location /.well-known/acme-challenge/ {{
        alias {alias}/;
        try_files $uri =404;
    }}
}}""".format(domain=domain, alias=alias)
    with open(vhost_conf, 'w') as fd:
        fd.write(vhost)
    os.chmod(vhost_conf, 0o644)
    reload_nginx()
    # Write challenge file
    with open('{0}/{1}'.format(alias, token), 'w') as fd:
        fd.write("{0}.{1}".format(token, thumbprint))
    return alias


def create_key(key_path, key_type=OpenSSL.crypto.TYPE_RSA, bits=2048):
    """
    Returns created private key and writes in into key_path
    Params:
        key_path, str, writable path for key
        key_type, int, SSL key type
        bits, int, the number of bits of the key
    Returns:
        string with private key
    """
    try:
        with open(key_path, 'r') as fd:
            private_key = fd.read()
    except:
        key = OpenSSL.crypto.PKey()
        key.generate_key(key_type, bits)
        private_key = OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key)
        print('{0} Can not open key {1}, generating new'
              .format(time.strftime("%b %d %H:%M:%S"), key_path))
        if not os.path.isdir(os.path.dirname(key_path)):
            os.mkdir(os.path.dirname(key_path))
        with open(key_path, 'wb') as fd:
            fd.write(private_key)
        os.chmod(key_path, 0o400)
    return private_key


def create_csr(key, altnames):
    """
    Generates CSR
    Params:
        key, str, private key
        altnames, list, dns alternative names
    Returns:
        string with CSR in DER format
    """
    sna = ', '.join(['DNS:{0}'.format(i) for i in altnames]).encode('utf8')
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = altnames[0]
    req.add_extensions([OpenSSL.crypto.X509Extension(
        'subjectAltName'.encode('utf8'), critical=False, value=sna)])
    pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    req.set_pubkey(pk)
    req.set_version(2)
    req.sign(pk, "sha256")
    return OpenSSL.crypto.dump_certificate_request(
            OpenSSL.crypto.FILETYPE_ASN1, req)


def b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


def sign_message(key, message, digest='sha256'):
    """
    Signs provided message with key
    Params:
        key, str, private key
        message, str, message to sign
        digest, str, digest type
    Returns:
        string with signed message
    """
    pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    return OpenSSL.crypto.sign(pk, message.encode('utf8'), 'sha256')


def jws(key):
    """ Returns JWS dict from string private key """
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
                "e": b64(binascii.unhexlify(exponent.encode('utf8'))),
                "kty": "RSA",
                "n": b64(binascii.unhexlify(modulus.encode('utf8')))}}
    return header


def send_signed_request(url, payload, key):
    """
    Send signed request to ACME CA
    Params:
        url, str, url for request
        payload, any type, any payload you want to send, usually dict
        key, str, private key contents
    """
    payload64 = b64(json.dumps(payload).encode('utf8'))
    protected = jws(key)
    protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
    protected64 = b64(json.dumps(protected).encode('utf8'))
    signature = sign_message(key, "{0}.{1}".format(protected64, payload64))
    data = json.dumps({
        "protected": protected64,
        "payload": payload64,
        "signature": b64(signature)})
    try:
        resp = urlopen(url, data.encode('utf8'))
        return resp.getcode(), resp.read()
    except Exception as e:
        return getattr(e, "code", None), getattr(e, "read", e.__str__)()


def set_arguments():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '-k',
            '--private-key',
            dest='private_key',
            default='/etc/ssl/private/letsencrypt-account.key',
            type=str,
            help=('path to letsencrypt account private key, '
                  'default: /etc/ssl/private/letsencrypt-account.key'))
    parser.add_argument(
            '--domain-private-key',
            dest='domain_key',
            type=str,
            default='/etc/ssl/private/letsencrypt-domain.key',
            help=('path to domain private key, '
                  'default: /etc/ssl/private/letsencrypt-domain.key'))
    parser.add_argument(
            '-o',
            '--output',
            dest='cert_path',
            type=str,
            default='/etc/ssl/private/letsencrypt-domain.pem',
            help='certificate path, default: /etc/ssl/private/letsencrypt.pem')
    parser.add_argument(
            '-d',
            '--domain',
            dest='domain',
            type=str,
            action='append',
            required=True,
            help='domain name, can be repeated for SAN')
    parser.add_argument(
            '--virtual-host',
            dest='vhost',
            type=str,
            default='/etc/nginx/sites-enabled/0-letsencrypt',
            help=('path to nginx virtual host for challenge completion, '
                  'default: /etc/nginx/sites-enabled/0-letsencrypt'))
    parser.add_argument(
            '--debug',
            dest='debug',
            action='store_true',
            help=("don't delete intermediate files for debugging"))
    return parser.parse_args()


def main():

    def _cleanup(files, directory=None):
        if not args.debug:
            for f in files:
                print('{0} removing {1}'
                        .format(time.strftime("%b %d %H:%M:%S"), f))
                os.remove(f)
            if directory:
                print('{0} removing {1}'
                        .format(time.strftime("%b %d %H:%M:%S"), directory))
                os.rmdir(directory)

    def _log(message, exit_with_error=False):
        print('{0} {1}'.format(time.strftime("%b %d %H:%M:%S"), message))
        if exit_with_error:
            try:
                _cleanup(
                        [args.vhost, '{0}/{1}'.format(to_clean, token)],
                        to_clean)
                reload_nginx()
            except:
                pass
            sys.exit(1)

    args = set_arguments()
# Generate new 2048 bit account, domain private keys only if not set
    try:
        private_key = create_key(args.private_key)
        domain_key = create_key(args.domain_key)
    except Exception as e:
        _log('Error creating key {0} {1}'.format(type(e).__name__, e), 1)
    csr = create_csr(domain_key, args.domain)
    _log('Trying to register account key')
    code, result = send_signed_request(
            CA + "/acme/new-reg",
            {"resource": "new-reg", "agreement": TOS},
            private_key)
    if code == 201:
        _log('Registered!')
    elif code == 409:
        _log('Already registered!')
    else:
        _log('Error registering: {0} {1}'.format(code, result), 1)
# Solve challenge
    for domain in args.domain:
        _log('Requesting challenge')
        code, result = send_signed_request(
                CA + "/acme/new-authz",
                {
                    "resource": "new-authz",
                    "identifier": {"type": "dns", "value": domain},
                },
                private_key)
        if code != 201:
            _log(
                    'Error requesting challenges: {0} {1}'
                    .format(code, result), 1)
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges']
                     if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        accountkey_json = json.dumps(
                jws(private_key)['jwk'],
                sort_keys=True,
                separators=(',', ':'))
        thumbprint = b64(
                hashlib.sha256(accountkey_json.encode('utf8')).digest())
        _log('Adding nginx virtual host and completing challenge')
        _log('Creating file {0}'.format(args.vhost))
        try:
            to_clean = nginx_challenge(domain, token, thumbprint, args.vhost)
        except Exception as e:
            _log('Error adding virtual host {0} {1}'
                    .format(type(e).__name__, e), 1)
        code, result = send_signed_request(
                challenge['uri'],
                {
                    "resource": "challenge",
                    "keyAuthorization": "{0}.{1}".format(token, thumbprint),
                },
                private_key)
        if code != 202:
            _log(
                    "Error triggering challenge: {0} {1}"
                    .format(code, result), 1)
        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                _log("Error checking challenge: {0} {1}"
                     .format(e.code, json.loads(e.read().decode('utf8'))), 1)
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                _log('{0} verified!'.format(domain))
                break
            else:
                _log('{0} challenge did not pass: {1}'.format(
                    domain, challenge_status), 1)
        _cleanup(['{0}/{1}'.format(to_clean, token)], to_clean)
    _log('Signing certificate')
    code, result = send_signed_request(
            CA + "/acme/new-cert",
            {"resource": "new-cert", "csr": b64(csr)},
            private_key
    )
    if code != 201:
        _log("Error signing certificate: {0} {1}".format(code, result), 1)
    _log('Certificate signed!')
    try:
        _log('Getting chain from {0}'.format(CHAIN))
        resp = urlopen(CHAIN)
        chain_str = resp.read()
        if chain_str:
            chain_str = chain_str.decode('utf8')
    except Exception as e:
        _log('Error getting chain: {0} {1}'.format(type(e).__name__, e), 1)
    _log('Writing result file in {0}'.format(args.cert_path))
    try:
        with open(args.cert_path, 'w') as fd:
            fd.write(
                '''-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'''
                .format('\n'.join(textwrap.wrap(
                    base64.b64encode(result).decode('utf8'), 64))))
            fd.write(chain_str)
    except Exception as e:
        _log('Error writing cert: {0} {1}'.format(type(e).__name__, e), 1)
    _log('Sending HUP to nginx'.format(args.vhost))
    _cleanup([args.vhost])
    reload_nginx()


if __name__ == "__main__":
    main()
