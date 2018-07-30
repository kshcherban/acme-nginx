import argparse
import logging
from acme_nginx.AcmeV1 import AcmeV1
from acme_nginx.AcmeV2 import AcmeV2


def set_arguments():
    """
    Parses command line arguments
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
            default='/etc/nginx/sites-enabled/0-letsencrypt.conf',
            help=('path to nginx virtual host for challenge completion, '
                  'default: /etc/nginx/sites-enabled/0-letsencrypt.conf'))
    parser.add_argument(
            '--debug',
            dest='debug',
            action='store_true',
            help="don't delete intermediate files for debugging")
    parser.add_argument(
            '--acme-v1',
            dest='acmev1',
            action='store_true',
            help='use ACME v1 api version')
    parser.add_argument(
            '--dns-provider',
            dest='dns_provider',
            choices=['digitalocean'])
    parser.add_argument(
            '--staging',
            action='store_true',
            help='use staging api endpoint for testing')
    parser.add_argument(
            '-V',
            '--version',
            action='version',
            version='acme-nginx {0}'.format(AcmeV2.version()))
    return parser.parse_args()


def main():
    args = set_arguments()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=log_level)
    log = logging.getLogger('acme')
    if args.acmev1:
        Acme = AcmeV1
        if args.staging:
            api_url = 'https://acme-staging.api.letsencrypt.org'
        else:
            api_url = 'https://acme-v01.api.letsencrypt.org'
    else:
        Acme = AcmeV2
        if args.staging:
            api_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        else:
            api_url = 'https://acme-v02.api.letsencrypt.org/directory'
    acme = Acme(
        api_url=api_url,
        logger=log,
        domains=args.domain,
        account_key=args.private_key,
        domain_key=args.domain_key,
        vhost=args.vhost,
        cert_path=args.cert_path,
        debug=args.debug,
        dns_provider=args.dns_provider
    )
    acme.get_certificate()
