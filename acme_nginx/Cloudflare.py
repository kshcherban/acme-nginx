import json
from os import getenv

try:
    from urllib.request import urlopen, Request  # Python 3
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, Request  # Python 2
    from urllib2 import HTTPError


class Cloudflare(object):
    def __init__(self):
        self.token = getenv("API_TOKEN")
        self.api = "https://api.cloudflare.com/client/v4"
        if not self.token:
            raise Exception("API_TOKEN not found in environment")

    def determine_domain(self, domain):
        """Determine registered domain in API
        Returns zone id
        """
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.token),
        }
        api = "{0}/zones?name={1}".format(self.api, domain)
        response = urlopen(Request(api, headers=request_headers))
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
        domains = json.loads(response.read().decode("utf8"))["result"]
        for d in domains:
            if d["name"] in domain:
                return d["id"]

    def create_record(self, name, data, domain):
        """
        Create DNS record
        Params:
            name, string, record name
            data, string, record data
            domain, string, dns domain
        Return:
            record_id, string, created record id
        """
        zone_id = self.determine_domain(domain)
        api = "{0}/zones/{1}/dns_records".format(self.api, zone_id)
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.token),
        }
        request_data = {
            "type": "TXT",
            "ttl": 300,
            "name": name,
            "content": data,
            "proxied": False,
        }
        try:
            response = urlopen(
                Request(
                    api,
                    data=json.dumps(request_data).encode("utf8"),
                    headers=request_headers,
                )
            )
        except HTTPError as e:
            raise Exception(e.read().decode("utf8"))
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
        return json.loads(response.read().decode("utf8"))["result"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        Params:
            record, string, record id number
            domain, string, dns domain
        """
        zone_id = self.determine_domain(domain)
        api = "{0}/zones/{1}/dns_records/{2}".format(self.api, zone_id, record)
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.token),
        }
        request = Request(
            api, data=json.dumps({}).encode("utf8"), headers=request_headers
        )
        # this is hack around urllib to send DELETE request
        request.get_method = lambda: "DELETE"
        try:
            response = urlopen(request)
        except HTTPError as e:
            raise Exception(e.read().decode("utf8"))
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
