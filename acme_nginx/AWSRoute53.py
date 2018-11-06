import boto3


class AWSRoute53(object):
    def __init__(self):
        self.session = boto3.Session()
        self.client = self.session.client('route53')

    def determine_domain(self, domain):
        """
        Determine registered domain in API and return it's hosted zone id
        Params:
            domain, string, domain name that is be part of account's hosted zones
        Returns:
            zone_id, string, hosted zone id of matching domain
        """
        if not domain.endswith('.'):
            domain = domain + '.'
        # use paginator to iterate over all hosted zones
        paginator = self.client.get_paginator('list_hosted_zones')
        # https://github.com/boto/botocore/issues/1535 result_key_iters is undocumented
        for page in paginator.paginate().result_key_iters():
            for result in page:
                if result['Name'] in domain:
                    return result['Id']

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
