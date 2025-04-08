import json
from os import getenv

from urllib.request import urlopen, Request
from urllib.error import HTTPError


class DigitalOcean(object):
    def __init__(self):
        self.token = getenv("API_TOKEN")
        self.api = "https://api.digitalocean.com/v2/domains"
        if not self.token:
            raise Exception("API_TOKEN not found in environment")

    def determine_domain(self, domain):
        """Determine registered domain in API"""
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.token),
        }
        response = urlopen(Request(self.api, headers=request_headers))
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
        domains = json.loads(response.read().decode("utf8"))["domains"]
        for d in domains:
            if d["name"] in domain:
                return d["name"]

    def create_record(self, name, data, domain):
        """
        Create DNS record
        Params:
            name, string, record name
            data, string, record data
            domain, string, dns domain
        Return:
            record_id, int, created record id
        """
        registered_domain = self.determine_domain(domain)
        api = self.api + "/" + registered_domain + "/records"
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.token),
        }
        request_data = {"type": "TXT", "ttl": 300, "name": name, "data": data}
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
        if response.getcode() != 201:
            raise Exception(json.loads(response.read().decode("utf8")))
        return json.loads(response.read().decode("utf8"))["domain_record"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        Params:
            record, int, record id number
            domain, string, dns domain
        """
        registered_domain = self.determine_domain(domain)
        api = self.api + "/" + registered_domain + "/records/" + str(record)
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
        if response.getcode() != 204:
            raise Exception(json.loads(response.read().decode("utf8")))
