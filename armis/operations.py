""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from datetime import datetime
from dateutil.tz import tzlocal
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('armis')


class Armis:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get('verify_ssl')
        self.secret = config.get('api_key')
        self.token = self.token if self.token else None
        self.exp_time = self.exp_time if self.exp_time else datetime.now(tzlocal()).isoformat()

    def make_rest_call(self, endpoint, headers=None, params=None, payload=None, method='GET'):
        self.token = self.get_token()
        updated_headers = headers
        updated_headers["accept"] = 'application/json'
        updated_headers["Authorization"] = str(self.token)
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.info('Request URL {}'.format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, data=str(payload), headers=updated_headers,
                                        params=params, verify=self.verify_ssl)
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
                        error_msg = "{}: {}".format(err_resp.get('error').get('code'),
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
        endpoint = '{0}{1}'.format(self.server_url, '/access_token/')
        if self.token is None or self.exp_time < datetime.now(tzlocal()).isoformat():
            resp = (requests.request('POST', endpoint, params={'secret_key': self.secret})).json()
            self.token = resp.get('data').get('access_token')
            self.exp_time = resp.get('data').get('expiration_utc')

        return self.token


def get_alerts(config, params):
    arm = Armis(config)
    max_alerts = params.get('max_alerts')
    time_frame = params.get('time_frame')
    alert_id = params.get('alert_id')
    risk_level = params.get('risk_level')
    status = params.get('status')
    alert_type = params.get('alert_type')
    query_string = 'in:alerts'
    if time_frame:
        query_string += f' timeFrame:"{time_frame}"'
    else:
        query_string += f' timeFrame:"30 Days"'
    if alert_id:
        query_string += f' alertId:({alert_id})'
    if risk_level:
        risk_levels = ','.join(risk_level)
        query_string += f' riskLevel:{risk_levels}'
    if status:
        statuses = ','.join(status)
        query_string += f'status:{statuses}'
    if alert_type:
        alert_types = ','.join(status)
        query_string += f' type:{alert_types}'
    if max_alerts:
        params['length'] = str(max_alerts)
    params['aql'] = query_string
    return arm.make_rest_call('/search/', params=params)


def get_devices(config, params):
    arm = Armis(config)
    name = params.get('name')
    device_id = params.get('device_id')
    mac_address = params.get('mac_address')
    ip_address = params.get('ip_address')
    device_type = params.get('device_type')
    max_devices = params.get('max_devices')
    risk_level = params.get('risk_level')
    time_frame = params.get('time_frame')
    query_string = 'in:devices'
    if time_frame:
        query_string += f' timeFrame:"{time_frame}"'
    else:
        query_string += f' timeFrame:"30 Days"'
    if name:
        query_string += f' name:({name})'
    if device_id:
        query_string += f' deviceId:({device_id})'
    if mac_address:
        query_string += f' macAddress:({mac_address})'
    if ip_address:
        query_string += f' ipAddress:({ip_address})'
    if device_type:
        type_list = device_type.split(',')
        new_list = []
        for item in type_list:
            item = f'"{item}"'
            new_list.append(item)
        device_types = ','.join(new_list)
        query_string += f' type:{device_types}'
    if risk_level:
        risk_levels = ','.join(risk_level)
        query_string += f' riskLevel:{risk_levels}'
    if max_devices:
        params['length'] = str(max_devices)
    params['aql'] = query_string
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
    return arm.make_rest_call(endpoint=endpoint, headers=headers, payload=payload, method='PATCH')


def add_tags_to_device(config, params):
    arm = Armis(config)
    device_id = params.get('device_id')
    tags = params.get('tags')
    taglist = tags.split(',')
    endpoint = f'/devices/{device_id}/tags/'
    payload = {
        'tags': taglist
    }
    return arm.make_rest_call(endpoint=endpoint, payload=payload, method='POST')


def remove_tags_from_device(config, params):
    arm = Armis(config)
    device_id = params.get('device_id')
    tags = params.get('tags')
    taglist = tags.split(',')
    endpoint = f'/devices/{device_id}/tags/'
    payload = {
        'tags': taglist
    }
    return arm.make_rest_call(endpoint=endpoint, payload=payload, method='DELETE')


def get_alerts_by_asq(config, params):
    arm = Armis(config)
    query_string = params.get('query_string')
    max_alerts = params.get('max_alerts')
    query_string = 'in:alerts {}'.format(query_string)
    if max_alerts:
        params['length'] = str(max_alerts)
    params['aql'] = query_string
    return arm.make_rest_call('/search/', params=params)


def get_devices_by_asq(config, params):
    arm = Armis(config)
    query_string = params.get('query_string')
    max_devices = params.get('max_devices')
    query_string = 'in:devices {}'.format(query_string)
    if max_devices:
        params['length'] = str(max_devices)
    params['aql'] = query_string
    return arm.make_rest_call('/search/', params=params)


def _check_health(config):
    arm = Armis(config)
    token = arm.get_token()
    if token:
        logger.info('connector available')
        return True


operations = {
    'get_alerts': get_alerts,
    'update_alert_status': update_alert_status,
    'get_alerts_by_asq': get_alerts_by_asq,
    'add_tags_to_device': add_tags_to_device,
    'remove_tags_from_device': remove_tags_from_device,
    'get_devices': get_devices,
    'get_devices_by_asq': get_devices_by_asq
}
