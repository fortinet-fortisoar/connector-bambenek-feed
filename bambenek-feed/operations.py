""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import requests
import base64
import csv
import re
import gzip
from io import StringIO
import time
import arrow

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('bambenek-feed')

FEED_MAPPING = {
    'DGA Domain': {
        'url': '{server_url}/feeds/dga-feed.gz',
        "fields": ['value', 'description', 'date_created', 'manpage']},
    'High-Confidence DGA Domain': {
        'url': '{server_url}/feeds/dga-feed-high.gz',
        "fields": ['value', 'description', 'date_created', 'manpage']},
    "C2 All Indicator": {
        "url": '{server_url}/feeds/dga/c2-masterlist.txt',
        "fields": ["value", "ip", "nsname", "nsip", "description", "manpage"]},
    'High-Confidence C2 All Indicator': {
        'url': '{server_url}/feeds/dga/c2-masterlist-high.txt',
        "fields": ["value", "ip", "nsname", "nsip", "description", "manpage"]},
    "C2 IP": {
        "url": "{server_url}/feeds/dga/c2-ipmasterlist.txt",
        "fields": ["value", "description", "date_created", "manpage"]},
    "High-Confidence C2 IP": {
        "url": "{server_url}/feeds/dga/c2-ipmasterlist-high.txt",
        "fields": ["value", "description", "date_created", "manpage"]},
    "C2 Domain": {
        "url": '{server_url}/feeds/dga/c2-dommasterlist.txt',
        "fields": ["value", "description", "date_created", "manpage"]},
    "High-Confidence C2 Domain": {
        "url": '{server_url}/feeds/dga/c2-dommasterlist-high.txt',
        "fields": ["value", "description", "date_created", "manpage"]},
    "Phishing Domain": {
        "url": '{server_url}/feeds/maldomainml/phishing-master.txt',
        "fields": ["hostname", "registered_domain", "ipv4_address", "asn", "netblock", "description",
                   "ASN or netblock are pipe delimieted"]},
    "Malware Domain": {
        "url": '{server_url}/feeds/maldomainml/malware-master.txt',
        "fields": ["hostname", "registered_domain", "ipv4_address", "asn", "netblock", "description",
                   "ASN_or_netblock"]},
    "Sinkhole": {
        "url": '{server_url}/feeds/sinkhole/latest.csv',
        "fields": ["value", "owner"]
    }
}


def validate_response(response, health_call=False):
    try:
        if response.ok:
            content_type = response.headers["Content-Type"]
            if health_call:
                return True
            if 'text/csv' in content_type or 'text/plain' in content_type:  # check the type
                f = (line.decode('utf-8') for line in response.iter_lines() if line)
                reader = csv.reader(f, delimiter=',', quotechar='"')
                return reader
            elif 'application/x-gzip' in content_type:
                response_content = gzip.decompress(response.content)
                input_file = StringIO(
                    response_content.decode('utf-8') if isinstance(response_content, bytes) else response_content)
                reader = csv.reader(input_file, delimiter=",", quotechar='"')
                return reader
        else:
            raise ConnectorError(
                'Fail To request API {0} response is : {1}'.format(str(response.url), str(response.text)))
    except Exception as e:
        raise ConnectorError(str(e))


def _get_config(config):
    try:
        server_url = config.get('server_url').strip('/')
        username = config.get("username", None)
        password = config.get("password", None)
        verify_ssl = config.get("verify_ssl", True)
        if server_url[:7] != 'http://' and server_url[:8] != 'https://':
            server_url = 'https://{}'.format(str(server_url))
        if (username and not password) or (password and not username):
            raise ConnectorError("Provide both Username and Password")
        return server_url, username, password, verify_ssl
    except Exception as Err:
        raise ConnectorError(Err)


def create_basic_auth(username, password):
    auth = '{username}:{password}'.format(username=username, password=password)
    credentials = base64.b64encode(bytes(auth, 'UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic {credentials}'.format(credentials=credentials)}
    return headers


def make_request(config, endpoint, parameters=None, method='GET', health_call=False):
    server_url, username, password, verify_ssl = _get_config(config)
    headers = {}
    url = endpoint.format(server_url=server_url)
    if username and password:
        headers = create_basic_auth(username, password)
    logger.debug('url: {}'.format(url))
    try:
        api_response = requests.request(method=method, url=url, params=parameters, verify=verify_ssl, headers=headers)
        return validate_response(api_response, health_call=health_call)
    except Exception as e:
        raise ConnectorError(str(e))


def convert_to_json(data, feed_name):
    result = []
    generatedAt = None
    for row in data:
        if len(row) < 2 and 'Feed generated at:' in row[0]:
            generatedAt = re.sub('.*Feed generated at: ([0-9 :-]*)', '\\1', row[0]).strip()
            try:
                d2 = time.strptime(generatedAt, "%a %b  %d %H:%M:%S UTC %Y")
                generatedAt = arrow.get(d2).format('YYYY-MM-DD HH:mm')
            except:
                generatedAt = generatedAt.strip('UTC').strip()
        if len(row) == len(FEED_MAPPING.get('{feed_name}'.format(feed_name=feed_name)).get('fields')):
            if '#' not in row[0]:
                result.append(
                    dict(list(zip(FEED_MAPPING.get('{feed_name}'.format(feed_name=feed_name)).get('fields'), row))))
    return {"generatedAt": generatedAt, "feed": result}


def filter_duplicate(data):
    seen = set()
    filtered_data = [x for x in data if [x['value'] not in seen, seen.add(x['value'])][0]]
    return filtered_data


def fetch_indicators(config, params, **kwargs):
    feed_family_type = params.get('feed_family_types')
    high_confidence = params.get('high_confidence', False)
    output_mode = params.get('output_mode')
    create_pb_id = params.get("create_pb_id")
    feed_name = ('High-Confidence ' if high_confidence else '') + '{feed_family_type}'.format(
        feed_family_type=feed_family_type)
    url = '{feed_type}'.format(feed_type=FEED_MAPPING.get(feed_name).get('url'))
    api_response = make_request(config, url)
    result = convert_to_json(api_response, feed_name)
    if output_mode == 'Create as Feed Records in FortiSOAR':
        filtered_data = filter_duplicate(result.get('feed'))
        result['feed'] = filtered_data
        trigger_ingest_playbook(result.get('feed'), create_pb_id, parent_env=kwargs.get('env', {}), batch_size=2000)
        logger.info("Successfully triggered playbooks to create feed records")
        return {"generatedAt": result.get('generatedAt'),
                "message": "Successfully triggered playbooks to create feed records"}
    else:
        return result


def _check_health(config):
    try:
        url = '{service}'.format(service=FEED_MAPPING.get('C2 IP').get('url'))
        api_response = make_request(config, url, health_call=True)
        if api_response:
            return True
    except Exception as e:
        raise ConnectorError(str(e))


operations = {
    'fetch_indicators': fetch_indicators
}
