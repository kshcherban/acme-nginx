import boto3


class AWSRoute53(object):
    def __init__(self):
        self.session = boto3.Session()
        self.client = self.session.client('route53')

    def __get_domains(self, next_zone=None, next_dns=None, data=[]):
        """ Recursively get all hosted dns zones """
        if not next_zone:
            out = self.client.list_hosted_zones_by_name()
        else:
            out = self.client.list_hosted_zones_by_name(DNSName=next_dns, HostedZoneId=next_zone)
        for i in out['HostedZones']:
            data.append((i['Name'], i['Id']))
        if out['IsTruncated']:
            self.__get_domains(
                    next_zone=out['NextHostedZoneId'],
                    next_dns=out['NextDNSName'],
                    data=data)
        else:
            return

    def determine_domain(self, domain):
        """ Determine registered domain in API and return hosted zone id """
        if not domain.endswith('.'):
            domain = domain + '.'
        zones = []
        self.__get_domains(data=zones)
        for domain_set in zones:
            if domain_set[0] in domain:
                return domain_set[1]

    def create_record(self, name, data, domain):
        """
        Create TXT DNS record
        Params:
            name, string, record name
            data, string, record data
            domain, string, dns domain
        Return:
            record_id, int, created record id
        """
        zone_id = self.determine_domain(domain)
        if not zone_id:
            raise Exception('Hosted zone for domain {0} not found'.format(domain))
        response = self.client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'TXT',
                            'TTL': 60,
                            'ResourceRecords': [
                                {
                                    'Value': '"{0}"'.format(data)
                                }
                            ]
                        }
                    }
                ]
            }
        )
        waiter = self.client.get_waiter('resource_record_sets_changed')
        waiter.wait(Id=response['ChangeInfo']['Id'])
        return {'name': name, 'data': data}

    def delete_record(self, record, domain):
        """
        Delete TXT DNS record
        Params:
            record, dict, record dict with name, data keys
            domain, string, dns domain
        """
        zone_id = self.determine_domain(domain)
        self.client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': record['name'],
                            'Type': 'TXT',
                            'TTL': 60,
                            'ResourceRecords': [
                                {
                                    'Value': '"{0}"'.format(record['data'])
                                }
                            ]
                        }
                    }
                ]
            }
        )
