import json
import logging
import requests
import shutil
import time
import warnings


"""For testing purposes:
logging.basicConfig(filename='pyunifi.log', level=logging.WARN,
                    format='%(asctime)s %(message)s')
"""
log = logging.getLogger(__name__)


class APIError(Exception):
    pass


def retry_login(func, *args, **kwargs):
    """To reattempt login if requests exception(s) occur at time of call"""
    def wrapper(*args, **kwargs):
        try:
            try:
                return func(*args, **kwargs)
            except (requests.exceptions.RequestException,
                    APIError) as err:
                log.warning("Failed to perform %s due to %s" % (func, err))
                controller = args[0]
                controller._login()
                return func(*args, **kwargs)
        except Exception as err:
            raise APIError(err)
    return wrapper


class Controller(object):

    """Interact with a UniFi controller.

    Uses the JSON interface on port 8443 (HTTPS) to communicate with a UniFi
    controller. Operations will raise unifi.controller.APIError on obvious
    problems (such as login failure), but many errors (such as disconnecting a
    nonexistant client) will go unreported.

    >>> from unifi.controller import Controller
    >>> c = Controller('192.168.1.99', 'admin', 'p4ssw0rd')
    >>> for ap in c.get_aps():
    ...     print 'AP named %s with MAC %s' % (ap.get('name'), ap['mac'])
    ...
    AP named Study with MAC dc:9f:db:1a:59:07
    AP named Living Room with MAC dc:9f:db:1a:59:08
    AP named Garage with MAC dc:9f:db:1a:59:0b

    """

    def __init__(self, host, username, password, port=8443,
                 version='v5', site_id='default', ssl_verify=True):
        """
        :param host: the address of the controller host; IP or name
        :param username: the username to log in with
        :param password: the password to log in with
        :param port: the port of the controller host
        :param version: the base version of the controller API [v4|v5]
        :param site_id: the site ID to connect to
        :param ssl_verify: Verify the controllers SSL certificate,
            can also be "path/to/custom_cert.pem"
        """
        if float(version[1:]) < 4:
            raise APIError("%s controllers no longer supported" % version)

        self.host = host
        self.port = port
        self.version = version
        self.username = username
        self.password = password
        self.site_id = site_id
        self.url = 'https://' + host + ':' + str(port) + '/'
        self.ssl_verify = ssl_verify

        if ssl_verify is False:
            warnings.simplefilter("default", category=requests.packages.
                                  urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.session.verify = ssl_verify

        log.debug('Controller for %s', self.url)
        self._login()

    @staticmethod
    def _jsondec(data):
        obj = json.loads(data)
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        else:
            return obj

    def _api_url(self):
        return self.url + 'api/s/' + self.site_id + '/'

    @retry_login
    def _read(self, url, params=None):
        # Try block to handle the unifi server being offline.
        r = self.session.get(url, params=params)
        return self._jsondec(r.text)

    def _api_read(self, url, params=None):
        return self._read(self._api_url() + url, params)

    @retry_login
    def _write(self, url, params=None):
        r = self.session.post(url, json=params)
        return self._jsondec(r.text)

    def _api_write(self, url, params=None):
        return self._write(self._api_url() + url, params)

    @retry_login
    def _update(self, url, params=None):
        r = self.session.put(url, json=params)
        return self._jsondec(r.text)

    def _api_update(self, url, params=None):
        return self._update(self._api_url() + url, params)

    def _login(self):
        log.debug('login() as %s', self.username)

        # XXX Why doesn't passing in the dict work?
        params = str({'username': self.username, 'password': self.password})
        login_url = self.url + 'api/login'

        r = self.session.post(login_url, params)
        if r.status_code is not 200:
            raise APIError("Login failed - status code: %i" % r.status_code)

    def _logout(self):
        log.debug('logout()')
        self._api_write('logout')

    def switch_site(self, name):
        """
        Switch to another site

        :param name: Site Name
        :return: True or APIError
        """
        for site in self.get_sites():
            if site['desc'] == name:
                self.site_id = site['name']
                return True
        raise APIError("No site %s found" % name)

    def get_alerts(self):
        """Return a list of all Alerts."""
        return self._api_write('stat/alarm')

    def get_alerts_unarchived(self):
        """Return a list of Alerts unarchived."""
        return self._api_write('stat/alarm', params={'archived': False})

    def get_statistics_last_24h(self):
        """Returns statistical data of the last 24h"""
        return self.get_statistics_24h(time())

    def get_statistics_24h(self, endtime):
        """Return statistical data last 24h from time"""

        params = {
            'attrs': ["bytes", "num_sta", "time"],
            'start': int(endtime - 86400) * 1000,
            'end': int(endtime - 3600) * 1000}
        return self._write(self._api_url() + 'stat/report/hourly.site', params)

    def get_statistics_hourly(self, start=None, end=None):
        """
        Hourly site stats method
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :return: an array of hourly stats objects for the current site
        NOTES:
         * defaults to the past 7*24 hours
         * "bytes" are no longer returned with controller version 4.9.1 and later
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/hourly.site', params)

    def get_ap_statistics_hourly(self, start=None, end=None, mac=None):
        """
        Hourly site stats method for a single access point or all access points
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param mac: AP MAC address to return stats for
        :return: an array of hourly stats objects for the current site
        NOTES:
         * defaults to the past 7*24 hours
         * "bytes" are no longer returned with controller version 4.9.1 and later
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac
        }
        return self._api_read('stat/report/hourly.ap', params)

    def get_statistics_5minutes(self, start=None, end=None):
        """
        5 minutes site stats method
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :return: an array of 5-minute stats objects for the current site
        NOTES:
         * defaults to the past 12 hours
         * this function/method is only supported on controller versions 5.5.* and later
         * make sure that the retention policy for 5 minutes stats is set to the correct value in
         * the controller settings
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (12 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/5minutes.site', params)

    def get_ap_statistics_5minutes(self, start=None, end=None, mac=None):
        """
        5 minutes site stats method for a single access point or all access points
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param mac: AP MAC address to return stats for
        :return: an array of 5-minute stats objects for the current site
        NOTES:
         * defaults to the past 12 hours
         * this function/method is only supported on controller versions 5.5.* and later
         * make sure that the retention policy for 5 minutes stats is set to the correct value in
         * the controller settings
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (12 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac
        }
        return self._api_read('stat/report/5minutes.ap', params)

    def get_statistics_daily(self, start=None, end=None):
        """
        Daily site stats method
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :return: an array of daily stats objects for the current site
        NOTES:
         * defaults to the past 52*7*24 hours
         * "bytes" are no longer returned with controller version 4.9.1 and later
         * make sure that the retention policy for 5 minutes stats is set to the correct value in
         * the controller settings
        """
        end = end if end else time.time() - (time.time() % 3600) * 1000
        start = start if start else end - (52 * 7 * 24 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/daily.site', params)

    def get_ap_statistics_daily(self, start=None, end=None, mac=None):
        """
        Daily site stats method for a single access point or all access points

        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param mac: AP MAC address to return stats for
        :return: an array of daily stats objects for the current site
        NOTES:
         * defaults to the past 52*7*24 hours
         * "bytes" are no longer returned with controller version 4.9.1 and later
         * make sure that the retention policy for 5 minutes stats is set to the correct value in
         * the controller settings
        """
        end = end if end else time.time() - (time.time() % 3600) * 1000
        start = start if start else end - (52 * 7 * 24 * 3600 * 1000)
        attributes = [
            'bytes',
            'wan-tx_bytes',
            'wan-rx_bytes',
            'wlan_bytes',
            'num_sta',
            'lan-num_sta',
            'wlan-num_sta',
            'time'
        ]
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac
        }
        return self._api_read('stat/report/daily.ap', params)

    def get_user_statistics_5minutes(self, mac, start=None, end=None, attributes=None):
        """
        5 minutes stats method for a single user/client device
        :param mac: MAC address of user/client device to return stats for
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               rx_bytes, tx_bytes, signal, rx_rate, tx_rate, rx_retries, tx_retries, rx_packets, tx_packets
               default is ['rx_bytes', 'tx_bytes']
        NOTES:
        * defaults to the past 12 hours
        * only supported with UniFi controller versions 5.8.X and higher
        * make sure that the retention policy for 5 minutes stats is set to the correct value in
          the controller settings
        * make sure that "Clients Historical Data" has been enabled in the UniFi controller settings in the Maintenance section
        :return: an array of 5-minute stats objects for a single user/client device
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (12 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'rx_bytes', 'tx_bytes']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac,
        }
        return self._api_read('stat/report/5minutes.user', params)

    def get_user_statistics_hourly(self, mac, start=None, end=None, attributes=None):
        """
        Hourly stats method for a single user/client device
        :param mac: MAC address of user/client device to return stats for
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               rx_bytes, tx_bytes, signal, rx_rate, tx_rate, rx_retries, tx_retries, rx_packets, tx_packets
               default is ['rx_bytes', 'tx_bytes']
        NOTES:
        * defaults to the past 7*24 hours
        * only supported with UniFi controller versions 5.8.X and higher
        * make sure that "Clients Historical Data" has been enabled in the UniFi controller settings in the Maintenance section
        :return: an array of hourly stats objects for a single user/client device
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'rx_bytes', 'tx_bytes']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac,
        }
        return self._api_read('stat/report/hourly.user', params)

    def get_user_statistics_daily(self, mac, start=None, end=None, attributes=None):
        """
        Daily stats method for a single user/client device
        :param mac: MAC address of user/client device to return stats for
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               rx_bytes, tx_bytes, signal, rx_rate, tx_rate, rx_retries, tx_retries, rx_packets, tx_packets
               default is ['rx_bytes', 'tx_bytes']
        NOTES:
        * defaults to the past 52*7*24 hours
        * only supported with UniFi controller versions 5.8.X and higher
        * make sure that "Clients Historical Data" has been enabled in the UniFi controller settings in the Maintenance section
        :return: an array of daily stats objects for a single user/client device
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (52 * 7 * 24 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'rx_bytes', 'tx_bytes']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
            'mac': mac,
        }
        return self._api_read('stat/report/daily.user', params)

    def get_gateway_statistics_5minutes(self, start=None, end=None, attributes=None):
        """
        5 minutes stats method for the gateway belonging to the current site
        :param mac: MAC address of user/client device to return stats for
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               mem, cpu, loadavg_5, lan-rx_errors, lan-tx_errors, lan-rx_bytes,
               lan-tx_bytes, lan-rx_packets, lan-tx_packets, lan-rx_dropped, lan-tx_dropped
               default is ['time', 'mem', 'cpu', 'loadavg_5']
        NOTES:
        * defaults to the past 12 hours
        * this function/method is only supported on controller versions 5.5.* and later
        * make sure that the retention policy for 5 minutes stats is set to the correct value in
          the controller settings
        * requires a USG
        :return: an array of 5-minute stats objects for the gateway belonging to the current site
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (12 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'mem', 'cpu', 'loadavg_5']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/5minutes.gw', params)

    def get_gateway_statistics_hourly(self, start=None, end=None, attributes=None):
        """
        Hourly stats method for the gateway belonging to the current site
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               mem, cpu, loadavg_5, lan-rx_errors, lan-tx_errors, lan-rx_bytes,
               lan-tx_bytes, lan-rx_packets, lan-tx_packets, lan-rx_dropped, lan-tx_dropped
               default is ['time', 'mem', 'cpu', 'loadavg_5']
        NOTES:
        * defaults to the past 7*24 hours
        * requires a USG
        :return: an array of hourly stats objects for the gateway belonging to the current site
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'mem', 'cpu', 'loadavg_5']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/hourly.gw', params)

    def get_gateway_statistics_daily(self, start=None, end=None, attributes=None):
        """
        Daily stats method for the gateway belonging to the current site
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param attributes: array containing attributes (strings) to be returned, valid values are:
               mem, cpu, loadavg_5, lan-rx_errors, lan-tx_errors, lan-rx_bytes,
               lan-tx_bytes, lan-rx_packets, lan-tx_packets, lan-rx_dropped, lan-tx_dropped
               default is ['time', 'mem', 'cpu', 'loadavg_5']
        NOTES:
        * defaults to the past 52*7*24 hours
        * requires a USG
        :return: an array of daily stats objects for the gateway belonging to the current site
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (52 * 7 * 24 * 3600 * 1000)
        attributes = ['time'] + attributes if attributes else ['time', 'mem', 'cpu', 'loadavg_5']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/daily.gw', params)

    def get_statistics_speedtest(self, start=None, end=None):
        """
        Method to fetch speed test results
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        NOTES:
        * defaults to the past 24 hours
        * requires a USG
        :return: an array of speed test result objects
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (24 * 3600 * 1000)
        attributes = ['xput_download', 'xput_upload', 'latency', 'time']
        params = {
            'start': start,
            'end': end,
            'attrs': attributes,
        }
        return self._api_read('stat/report/archive.speedtest', params)

    def get_statistics_ips_events(self, start=None, end=None, limit=10000):
        """
        Method to fetch IPS/IDS event
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param limit: Maximum number of events to return, defaults to 10000
        NOTES:
        * defaults to the past 24 hours
        * requires a USG
        * supported in UniFi controller versions 5.9.X and higher
        :return: an array of IPS/IDS event objects
        """
        end = end if end else time.time() * 1000
        start = start if start else end - (24 * 3600 * 1000)
        params = {
            'start': start,
            'end': end,
            '_limit': limit,
        }
        return self._api_read('stat/ips/event', params)

    def get_statistics_sessions(self, start=None, end=None, mac=None, client_type='all'):
        """
        Show all login sessions
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds
        :param mac: client MAC address to return sessions for (can only be used when start and end are also provided)
        :param client_type: client type to return sessions for, can be 'all', 'guest' or 'user'; default value is 'all'
        NOTES:
        * defaults to the past 7*24 hours
        :return: an array of login session objects for all devices or a single device

        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        params = {
            'start': start,
            'end': end,
            'type': client_type,
        }
        if mac:
            params['mac'] = mac
        return self._api_read('stat/session', params)

    def get_latest_client_sessions(self, mac, limit=5):
        """
        Show latest 'n' login sessions for a single client device
        :param mac: client MAC address
        :param limit: maximum number of sessions to get (default value is 5)
        :return: an array of latest login session objects for given client device
        """
        params = {
            'mac': mac,
            '_limit': limit,
            '_sort': '-assoc_time'
        }
        return self._api_read('stat/session', params)

    def get_statistics_authorizations(self, start=None, end=None):
        """
        Show all authorizations
        :param start: Unix timestamp in milliseconds
        :param end: Unix timestamp in milliseconds

        NOTES:
        * defaults to the past 7*24 hours
        :return: an array of authorization objects

        """
        end = end if end else time.time() * 1000
        start = start if start else end - (7 * 24 * 3600 * 1000)
        params = {
            'start': start,
            'end': end,
        }

        return self._api_read('stat/authorization', params)

    def get_statistics_all_users(self, hours_to_go_back=8760):
        """
        List all client devices ever connected to the site
        :param hours_to_go_back: hours to go back (default is 8760 hours or 1 year)
        :return: an array of client device objects
        NOTES:
        * <hours_to_go_back> is only used to select clients that were online within that period,
          the returned stats per client are all-time totals, irrespective of the value of <hours_to_go_back>
        """
        params = {
            'type': 'all',
            'conn': 'all',
            'within': hours_to_go_back
        }

        return self._api_read('stat/alluser', params)

    def get_events(self):
        """Return a list of all Events."""
        return self._api_read('stat/event')

    def get_aps(self):
        """Return a list of all APs,
        with significant information about each.
        """
        # Set test to 0 instead of NULL
        params = {'_depth': 2, 'test': 0}
        return self._api_read('stat/device', params)

    def get_client(self, mac):
        """Get details about a specific client"""

        # stat/user/<mac> works better than stat/sta/<mac>
        # stat/sta seems to be only active clients
        # stat/user includes known but offline clients
        return self._api_read('stat/user/' + mac)[0]

    def get_clients(self):
        """Return a list of all active clients,
        with significant information about each.
        """
        return self._api_read('stat/sta')

    def get_users(self):
        """Return a list of all known clients,
        with significant information about each.
        """
        return self._api_read('list/user')

    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""
        return self._api_read('list/usergroup')

    def get_sysinfo(self):
        """Return basic system informations."""
        return self._api_read('stat/sysinfo')

    def get_healthinfo(self):
        """Return health information."""
        return self._api_read('stat/health')

    def get_sites(self):
        """Return a list of all sites,
        with their UID and description"""
        return self._read(self.url + 'api/self/sites')

    def get_wlan_conf(self):
        """Return a list of configured WLANs
        with their configuration parameters.
        """
        return self._api_read('list/wlanconf')

    def _run_command(self, command, params={}, mgr='stamgr'):
        log.debug('_run_command(%s)', command)
        params.update({'cmd': command})
        return self._write(self._api_url() + 'cmd/' + mgr, params=params)

    def _mac_cmd(self, target_mac, command, mgr='stamgr', params={}):
        log.debug('_mac_cmd(%s, %s)', target_mac, command)
        params['mac'] = target_mac
        return self._run_command(command, params, mgr)

    def create_user(self, mac, user_group_id, name=None, note=None):
        """
        Create a new user/client-device
        :param mac: client MAC address
        :param user_group_id: _id value for the user group the new user/client-device should belong to which
        can be obtained from the output of list_usergroups()
        :param name: name to be given to the new user/client-device
        :param note: note to be applied to the new user/client-device
        :return: an array with a single object containing details of the new user/client-device on success,
         else return false
        """
        params = {
            'mac': mac,
            'usergroup_id': user_group_id,
        }
        if name:
            params['name'] = name

        if note:
            params['note'] = note
            params['noted'] = True

        return self._api_write('group/user', {'data': params})

    def set_client_note(self, user_id, note=None):
        """
        Add/modify/remove a client-device note
        :param user_id: id of the client-device to be modified
        :param note: note to be applied to the client-device
               NOTES:
                   when note is empty or not set, the existing note for the client-device will be removed and "noted"
                   attribute set to false
        :return: True on success
        """
        params = {
            'noted': True if note else False,
            'note': note
        }
        return self._api_write('upd/user/{}'.format(user_id), params)

    def set_client_name(self, user_id, name=None):
        """
        Add/modify/remove a client-device name
        :param user_id: id of the client-device to be modified
        :param name: name to be applied to the client-device
               NOTES:
                   when name is empty or not set, the existing name for the client-device will be removed
        :return: True on success
        """
        params = {
            'name': name,
        }
        return self._api_write('upd/user/{}'.format(user_id), params)

    def create_site(self, desc='desc'):
        """Create a new site.

        :param desc: Name of the site to be created.
        """
        return self._run_command('add-site', params={"desc": desc},
                                 mgr='sitemgr')

    def block_client(self, mac):
        """Add a client to the block list.

        :param mac: the MAC address of the client to block.
        """
        return self._mac_cmd(mac, 'block-sta')

    def unblock_client(self, mac):
        """Remove a client from the block list.

        :param mac: the MAC address of the client to unblock.
        """
        return self._mac_cmd(mac, 'unblock-sta')

    def disconnect_client(self, mac):
        """Disconnect a client.

        Disconnects a client, forcing them to reassociate. Useful when the
        connection is of bad quality to force a rescan.

        :param mac: the MAC address of the client to disconnect.
        """
        return self._mac_cmd(mac, 'kick-sta')

    def forget_clients(self, macs):
        """Forgets a client or clients.

        :param macs: array of client MAC addresses
        :return: True on success
        """
        return self._run_command('forget-sta', {'macs': macs})

    def restart_ap(self, mac):
        """Restart an access point (by MAC).

        :param mac: the MAC address of the AP to restart.
        """
        return self._mac_cmd(mac, 'restart', 'devmgr')

    def restart_ap_name(self, name):
        """Restart an access point (by name).

        :param name: the name address of the AP to restart.
        """
        if not name:
            raise APIError('%s is not a valid name' % str(name))
        for ap in self.get_aps():
            if ap.get('state', 0) == 1 and ap.get('name', None) == name:
                return self.restart_ap(ap['mac'])

    def archive_all_alerts(self):
        """Archive all Alerts"""
        return self._run_command('archive-all-alarms', mgr='evtmgr')

    def create_backup(self):
        """Ask controller to create a backup archive file

        ..warning:
            This process puts significant load on the controller
            and may render it partially unresponsive for other requests.

        :return: URL path to backup file
        """
        res = self._run_command('backup', mgr='system')
        return res[0]['url']

    def get_backup(self, download_path=None, target_file='unifi-backup.unf'):
        """
        :param download_path: path to backup; if None is given
            one will be created
        :param target_file: Filename or full path to download the
            backup archive to, should have .unf extension for restore.
        """
        if not download_path:
            download_path = self.create_backup()

        r = self.session.get(self.url + download_path, stream=True)
        with open(target_file, 'wb') as _backfh:
            return shutil.copyfileobj(r.raw, _backfh)

    def authorize_guest(self, guest_mac, minutes, up_bandwidth=None,
                        down_bandwidth=None, byte_quota=None, ap_mac=None):
        """
        Authorize a guest based on his MAC address.

        :param guest_mac: the guest MAC address: 'aa:bb:cc:dd:ee:ff'
        :param minutes: duration of the authorization in minutes
        :param up_bandwidth: up speed allowed in kbps
        :param down_bandwidth: down speed allowed in kbps
        :param byte_quota: quantity of bytes allowed in MB
        :param ap_mac: access point MAC address
        """
        cmd = 'authorize-guest'
        params = {'mac': guest_mac, 'minutes': minutes}

        if up_bandwidth:
            params['up'] = up_bandwidth
        if down_bandwidth:
            params['down'] = down_bandwidth
        if byte_quota:
            params['bytes'] = byte_quota
        if ap_mac:
            params['ap_mac'] = ap_mac
        return self._run_command(cmd, params=params)

    def unauthorize_guest(self, guest_mac):
        """
        Unauthorize a guest based on his MAC address.

        :param guest_mac: the guest MAC address: 'aa:bb:cc:dd:ee:ff'
        """
        cmd = 'unauthorize-guest'
        params = {'mac': guest_mac}
        return self._run_command(cmd, params=params)

    def get_firmware(self, cached=True, available=True,
                     known=False, site=False):
        """
        Return a list of available/cached firmware versions

        :param cached: Return cached firmwares
        :param available: Return available (and not cached) firmwares
        :param known: Return only firmwares for known devices
        :param site: Return only firmwares for on-site devices
        :return: List of firmware dicts
        """
        res = []
        if cached:
            res.extend(self._run_command('list-cached', mgr='firmware'))
        if available:
            res.extend(self._run_command('list-available', mgr='firmware'))

        if known:
            res = [fw for fw in res if fw['knownDevice']]
        if site:
            res = [fw for fw in res if fw['siteDevice']]
        return res

    def cache_firmware(self, version, device):
        """
        Cache the firmware on the UniFi Controller

        .. warning:: Caching one device might very well cache others,
            as they're on shared platforms

        :param version: version to cache
        :param device: device model to cache (e.g. BZ2)
        :return: True/False
        """
        return self._run_command(
            'download', mgr='firmware',
            params={'device': device, 'version': version})[0]['result']

    def remove_firmware(self, version, device):
        """
        Remove cached firmware from the UniFi Controller

        .. warning:: Removing one device's firmware might very well remove
            others, as they're on shared platforms

        :param version: version to cache
        :param device: device model to cache (e.g. BZ2)
        :return: True/false
        """
        return self._run_command(
            'remove', mgr='firmware',
            params={'device': device, 'version': version})[0]['result']

    def get_tag(self):
        """Get all tags and their member MACs"""
        return self._api_read('rest/tag')

    def upgrade_device(self, mac, version):
        """
        Upgrade a device's firmware to verion
        :param mac: MAC of dev
        :param version: version to upgrade to
        """
        self._mac_cmd(mac, 'upgrade', mgr='devmgr',
                      params={'upgrade_to_firmware': version})

    def provision(self, mac):
        """
        Force provisioning of a device
        :param mac: MAC of device
        """
        self._mac_cmd(mac, 'force-provision', mgr='devmgr')

    def get_setting(self, section=None, super=False):
        """
        Return settings for this site or controller

        :param super: Return only controller-wide settings
        :param section: Only return this/these section(s)
        :return: {section:settings}
        """
        res = {}
        settings = self._api_read('get/setting')
        if section and not isinstance(section, (list, tuple)):
            section = [section]

        for s in settings:
            s_sect = s['key']
            if (super and 'site_id' in s) or \
               (not super and 'site_id' not in s) or \
               (section and s_sect not in section):
                continue
            for k in ('_id', 'site_id', 'key'):
                s.pop(k, None)
            res[s_sect] = s
        return res

    def update_setting(self, settings):
        """
        Update settings

        :param settings: {section:{settings}}
        :return: resulting settings
        """
        res = []
        for sect, setting in settings.items():
            res.extend(self._api_write('set/setting/' + sect, setting))
        return res

    def update_user_group(self, group_id, down_kbps=-1, up_kbps=-1):
        """
        Update user group bandwidth settings

        :param group_id: Group ID to modify
        :param down_kbps: New bandwidth in KBPS for download
        :param up_kbps: New bandwidth in KBPS for upload
        """

        res = None
        groups = self.get_user_groups()

        for group in groups:
            if group["_id"] == group_id:
                # Apply setting change
                res = self._api_update("rest/usergroup/{0}".format(group_id), {
                    "qos_rate_max_down": down_kbps,
                    "qos_rate_max_up": up_kbps,
                    "name": group["name"],
                    "_id": group_id,
                    "site_id": self.site_id
                })
                return res

        raise ValueError("Group ID {0} is not valid.".format(group_id))

    def set_client_alias(self, mac, alias):
        """
        Set the client alias. Set to "" to reset to default
        :param mac: The MAC of the client to rename
        :param alias: The alias to set
        """
        client = self.get_client(mac)['_id']
        return self._api_update('rest/user/' + client, {'name': alias})

    def stat_voucher(self, create_time=None):
        """
        List Vouchers
        -------------
        :param create_time: Unix timestamp in seconds
        :return: an array of hotspot voucher objects
        """
        return self._api_read('stat/voucher', {'create_time': create_time} if create_time else {})

    def create_voucher(self, minutes_of_use, count_of_vouchers=1, quota=0, note=None, upload_limit_kbps=None,
                       down_limit_kbps=None, data_limit_mega_bytes=None):
        """
        Create voucher(s)
        -----------------
        :param minutes_of_use: minutes the voucher is valid after activation (expiration time)
        :param count_of_vouchers: number of vouchers to create, default value is 1
        :param quota: single-use or multi-use vouchers, value '0' is for multi-use, '1' is for single-use,
                      'n' is for multi-use n times
        :param note: note text to add to voucher when printing
        :param upload_limit_kbps: upload speed limit in kbps
        :param down_limit_kbps: download speed limit in kbps
        :param data_limit_mega_bytes: data transfer limit in MB
        :return: dict
        NOTES: please use the stat_voucher() method/function to retrieve the newly created voucher(s) by create_time
        """
        params = {
            'cmd': 'create-voucher',
            'expire': minutes_of_use,
            'n': count_of_vouchers,
            'quota': quota,
        }

        if note:
            params['note'] = note

        if upload_limit_kbps:
            params['up'] = upload_limit_kbps

        if down_limit_kbps:
            params['down'] = down_limit_kbps

        if data_limit_mega_bytes:
            params['bytes'] = data_limit_mega_bytes

        return self._api_write('cmd/hotspot', params)

    def revoke_voucher(self, voucher_id):
        """
        :param voucher_id: 24 char string; _id of the voucher to revoke
        :return: boolean?
        """
        params = {'cmd': 'delete-voucher'}
        if voucher_id:
            params['_id'] = voucher_id
        return self._api_read('cmd/hotspot', params)
