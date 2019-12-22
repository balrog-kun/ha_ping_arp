"""Track devices from the ARP table using ping."""
from collections import namedtuple
from datetime import timedelta
import logging
import subprocess
import re

import voluptuous as vol

from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import CONF_HOSTS
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util

_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = "exclude"
# Interval in minutes to exclude devices from a scan while they are home
CONF_HOME_INTERVAL = "home_interval"
CONF_IFACE = "iface"
CONF_PING_TIMEOUT = "ping_timeout"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOME_INTERVAL, default=0): cv.positive_int,
        vol.Optional(CONF_HOSTS, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_PING_TIMEOUT, default=2.0): vol.All(vol.Coerce(float), vol.Range(min=0, max=5)),
        vol.Optional(CONF_IFACE, default=''): cv.string,
    }
)

def get_scanner(hass, config):
    """Validate the configuration and return the scanner."""
    return ArpDeviceScanner(config[DOMAIN])

Device = namedtuple("Device", ["mac", "name", "ip", "last_update"])

def ip_mask_match(ip, mask):
    # Supported formats:
    # a.b.c.d/n
    # A.B.C.D
    # where a, b, c, d, n must be decimal numbers, and A, B, C, D
    # may be either a decimal number or a range (x-y)
    addr = ip.split('.', 3)
    if not addr:
        return False

    abcdn = re.match(r'([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)', mask)
    if abcdn:
        addr_num = (int(addr[0]) << 24) | (int(addr[1]) << 16) | (int(addr[2]) << 8) | (int(addr[3]) << 0)
        mask_num = (int(abcdn[1]) << 24) | (int(abcdn[2]) << 16) | (int(abcdn[3]) << 8) | (int(abcdn[4]) << 0)
        bits = int(abcdn[5])
        if bits < 1 or bits > 32:
            return False
        return addr_num >> (32 - bits) == mask_num >> (32 - bits)

    for a, b in zip(addr, mask.split('.', 3)):
        ip_num = int(a)
        xy = re.match(r'([0-9]+)-([0-9]+)', b)
        if xy:
            if ip_num < int(xy[1]) or ip_num > int(xy[2]):
                return False
        else:
            if ip_num != int(b):
                return False

    return True

class ArpDeviceScanner(DeviceScanner):
    """This class scans for devices using arp+ping."""

    exclude = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []

        self.hosts = config[CONF_HOSTS]
        self.exclude = config[CONF_EXCLUDE]
        minutes = config[CONF_HOME_INTERVAL]
        self._ping_timeout = config[CONF_PING_TIMEOUT]
        self._iface = config[CONF_IFACE]
        self.home_interval = timedelta(minutes=minutes)

        _LOGGER.debug("Scanner initialized")

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        _LOGGER.debug("last results %s", self.last_results)

        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        filter_named = [
            result.name for result in self.last_results if result.mac == device
        ]

        if filter_named:
            return filter_named[0]
        return None

    def get_extra_attributes(self, device):
        """Return the IP of the given device."""
        filter_ip = next(
            (result.ip for result in self.last_results if result.mac == device), None
        )
        return {"ip": filter_ip}

    def _update_info(self):
        """Scan the network for devices.

        Returns boolean if scanning successful.
        """

        last_results = []
        last_macs = []
        if self.home_interval:
            boundary = dt_util.now() - self.home_interval
            for device in self.last_results:
                if device.last_update > boundary:
                    last_results.append(device)
                    last_macs.append(device.mac)

        cmd = [ 'arp', '-a' ]
        if self._iface:
            cmd += [ '-i', self._iface ]
        _LOGGER.debug('Running ' + ' '.join(cmd) + '...')
        try:
            arp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            out, _ = arp.communicate() 
        except Exception as e:
            _LOGGER.error('Fail: ' + ' '.join(cmd) + ' resulted in ' + str(e))
            return False

        now = dt_util.now()
        for line in out.decode('utf-8').splitlines():
            # Format is: <hostname>|? (<ip>) at <mac> [<iftype>] on <iface>
            # The hostname is optional for us.  If we can't parse the IP or the
            # MAC the result is useless to us though so skip it.
            r = r'([a-zA-Z0-9_.-]+|\?) \((([0-9]+\.){3}[0-9]+)\) at (([0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2}) .*'
            m = re.match(r, line)
            if not m:
                continue

            if m[1] == '?':
                hostname = None
            else:
                hostname = m[1]
            ipv4 = m[2]
            mac = m[4]

            if mac in last_macs:
                continue

            for mask in self.hosts:
                if ip_mask_match(ipv4, mask):
                    break
            else:
                continue

            skip = False
            for mask in self.exclude:
                if ip_mask_match(ipv4, mask):
                    skip = True
                    break
            if skip:
                continue

            cmd = [ 'ping', '-n', '-q', '-c1', '-W' + str(self._ping_timeout) ]
            if self._iface:
                cmd += [ '-I', self._iface ]
            cmd += [ ipv4 ]
            _LOGGER.debug('Running ' + ' '.join(cmd) + '...')
            try:
                pinger = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                pinger.communicate()
                if pinger.returncode != 0:
                    continue
            except:
                continue

            last_results.append(Device(mac.upper(), hostname, ipv4, now))

        self.last_results = last_results

        _LOGGER.debug("arp scan done")
        return True
