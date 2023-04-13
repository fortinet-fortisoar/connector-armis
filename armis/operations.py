""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from datetime import datetime
import pytz
import requests
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

logger = get_logger('armis')


class Armis:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get('verify_ssl')
        self.secret = config.get('api_key')
        self.token = config.get("token")
        self.exp_time = config.get("exp_time", str(datetime.now(pytz.utc)))
        if self.token is None or (datetime.strptime(self.exp_time, '%Y-%m-%dT%H:%M:%S.%f%z') < datetime.now(pytz.utc)):
            self.get_token()
            config["token"] = self.token
            config["exp_time"] = self.exp_time
        self.connector_info = config.get("connector_info")
        if self.connector_info:
            update_connnector_config(connector_name=self.connector_info.get("connector_name"),
                                     version=self.connector_info.get("connector_version"),
                                     updated_config=config,
                                     configId=config.get("config_id"))

    def make_rest_call(self, endpoint, headers=None, params=None, payload=None, json_data=None, method='GET'):
        updated_headers = headers or {}
        updated_headers["accept"] = 'application/json'
        updated_headers["Authorization"] = str(self.token)
        service_endpoint = '{0}{1}{2}'.format(self.server_url, '/api/v1', endpoint)
        logger.info('Request URL {0}'.format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, data=payload, headers=updated_headers,
                                        params=params, json=json_data, verify=self.verify_ssl)
            if response.ok:
                content_type = response.headers.get('Content-Type')
                if response.text != "" and 'application/json' in content_type:
                    return response.json()
                else:
                    return response.content
            else:
                if response.text != "":
                    err_resp = response.json()
                    if "error" in err_resp:
                        error_msg = "{0}: {1}".format(err_resp.get('error').get('code'),
                                                      err_resp.get('error').get('message'))
                        raise ConnectorError(error_msg)
                else:
                    error_msg = '{0}: {1}'.format(response.status_code, response.reason)
                    raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def get_token(self):
        try:
            endpoint = '{0}{1}{2}'.format(self.server_url, '/api/v1', '/access_token/')
            params = {'secret_key': self.secret}
            response = requests.request('POST', endpoint, params=params)
            resp = response.json()
            if response.status_code == 200:
                self.token = resp['data']['access_token']
                self.exp_time = resp['data']['expiration_utc']
            else:
                raise ConnectorError('{0}'.format(resp.get('message')))
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Server URL')
        except Exception as e:
            raise ConnectorError('{0}'.format(e))


def get_alerts(config, params):
    arm = Armis(config)
    limit = params.get('limit')
    offset = params.get('offset')
    start_time = str(params.get('start_time'))
    alert_id = params.get('alert_id')
    risk_level = params.get('risk_level')
    status = params.get('status')
    alert_type = params.get('alert_type')
    site = params.get('site')
    query_string = 'in:alerts'
    start_time = start_time[:19]
    if start_time:
        query_string += f' after:{start_time}'
    if alert_id:
        if isinstance(alert_id, list):
            alert_ids = ','.join([str(item) for item in alert_id])
            query_string += f' alertId:({alert_ids})'
        else:
            query_string += f' alertId:({alert_id})'
    if risk_level:
        risk_levels = ','.join(risk_level)
        query_string += f' riskLevel:{risk_levels}'
    if status:
        statuses = ','.join(status)
        query_string += f' status:{statuses}'
    if alert_type:
        alert_types = ','.join([f'"{item}"' for item in alert_type])
        query_string += f' type:{alert_types}'
    if site:
        sites = ','.join([f'"{item}"' for item in [item.strip(" ") for item in site.split(',')]])
        query_string += f' site:{sites}'
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    params['aql'] = query_string
    return arm.make_rest_call('/search/', params=params)


def get_alerts_by_asq(config, params):
    arm = Armis(config)
    query_string = params.get('query_string')
    limit = params.get('limit')
    offset = params.get('offset')
    query = 'in:alerts'
    if query_string:
        query += f' {query_string}'
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    params['aql'] = query
    return arm.make_rest_call('/search/', params=params)


def update_alert_status(config, params):
    arm = Armis(config)
    alert_id = params.get('alert_id')
    status = params.get('status')
    endpoint = f'/alerts/{alert_id}/'
    payload = {
        'status': status
    }
    headers = {
        'content-type': 'application/x-www-form-urlencoded'
    }
    return arm.make_rest_call(endpoint, headers=headers, payload=payload, method='PATCH')


def get_devices(config, params):
    arm = Armis(config)
    limit = params.get('limit')
    offset = params.get('offset')
    device_name = params.get('device_name')
    device_id = params.get('device_id')
    mac_address = params.get('mac_address')
    ip_address = params.get('ip_address')
    device_type = params.get('device_type')
    risk_level = params.get('risk_level')
    time_frame = params.get('time_frame')
    site = params.get('site')
    query_string = 'in:devices'
    if time_frame:
        query_string += f' timeFrame:"{time_frame}"'
    if device_name:
        query_string += f' name:({device_name})'
    if device_id:
        if isinstance(device_id, list):
            device_ids = ','.join([str(item) for item in device_id])
            query_string += f' deviceId:({device_ids})'
        else:
            query_string += f' deviceId:({device_id})'
    if mac_address:
        query_string += f' macAddress:({mac_address})'
    if ip_address:
        query_string += f' ipAddress:({ip_address})'
    if device_type:
        device_types = ','.join([f'"{item}"' for item in [item.strip(" ") for item in device_type.split(',')]])
        query_string += f' type:{device_types}'
    if risk_level:
        risk_levels = ','.join(risk_level)
        query_string += f' riskLevel:{risk_levels}'
    if site:
        sites = ','.join([f'"{item}"' for item in [item.strip(" ") for item in site.split(',')]])
        query_string += f' site:{sites}'
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    params['aql'] = query_string
    return arm.make_rest_call('/search/', params=params)


def get_devices_by_asq(config, params):
    arm = Armis(config)
    query_string = params.get('query_string')
    limit = params.get('limit')
    offset = params.get('offset')
    query = 'in:devices'
    if query_string:
        query += f' {query_string}'
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    params['aql'] = query
    return arm.make_rest_call('/search/', params=params)


def update_device(config, params):
    arm = Armis(config)
    device_id = params.get('device_id')
    attributes = params.get('attributes')
    endpoint = f'/devices/{device_id}/'
    return arm.make_rest_call(endpoint, json_data=attributes, method='PATCH')


def add_device_tags(config, params):
    arm = Armis(config)
    device_id = params.get('device_id')
    tags = params.get('tags')
    taglist = tags.split(',')
    endpoint = f'/devices/{device_id}/tags/'
    payload = {
        'tags': taglist
    }
    return arm.make_rest_call(endpoint, json_data=payload, method='POST')


def remove_device_tags(config, params):
    arm = Armis(config)
    device_id = params.get('device_id')
    tags = params.get('tags')
    taglist = tags.split(',')
    endpoint = f'/devices/{device_id}/tags/'
    payload = {
        'tags': taglist
    }
    return arm.make_rest_call(endpoint, json_data=payload, method='DELETE')


def get_policies(config, params):
    arm = Armis(config)
    limit = params.get('limit')
    offset = params.get('offset')
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    return arm.make_rest_call('/policies/', params=params)


def update_policy(config, params):
    arm = Armis(config)
    policy_id = params.get('policy_id')
    attributes = params.get('attributes')
    endpoint = f'/policies/{policy_id}/'
    return arm.make_rest_call(endpoint, json_data=attributes, method='PATCH')


def get_reports(config, params):
    arm = Armis(config)
    return arm.make_rest_call('/reports/')


def get_vulnerability_matches(config, params):
    arm = Armis(config)
    input_type = params.get('input_type')
    ids = params.get('ids')
    limit = params.get('limit')
    offset = params.get('offset')
    if isinstance(ids, list):
        ids = ','.join([str(item) for item in ids])
    else:
        ids = str(ids)
    if limit:
        params['length'] = str(limit)
    if offset:
        params['from'] = str(offset)
    if input_type == 'Device IDs':
        params['device_ids'] = ids
    else:
        params['vulnerability_ids'] = ids
    return arm.make_rest_call('/vulnerability-match/', params=params)


def _check_health(config):
    try:
        arm = Armis(config)
        if arm.token is not None:
            return True
    except Exception as e:
        raise ConnectorError('{0}'.format(e))


operations = {
    'get_alerts': get_alerts,
    'get_alerts_by_asq': get_alerts_by_asq,
    'update_alert_status': update_alert_status,
    'get_devices': get_devices,
    'get_devices_by_asq': get_devices_by_asq,
    'update_device': update_device,
    'add_device_tags': add_device_tags,
    'remove_device_tags': remove_device_tags,
    'get_policies': get_policies,
    'update_policy': update_policy,
    'get_reports': get_reports,
    'get_vulnerability_matches': get_vulnerability_matches
}
