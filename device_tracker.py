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
CONF_PING_INCOMPLETE = "ping_incomplete"
CONF_FPING_INTERVAL = "fping_interval"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOME_INTERVAL, default=0): cv.positive_int,
        vol.Optional(CONF_HOSTS, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_PING_TIMEOUT, default=2.0): vol.All(vol.Coerce(float), vol.Range(min=0, max=5)),
        vol.Optional(CONF_PING_INCOMPLETE, default=False): cv.boolean,
        vol.Optional(CONF_IFACE, default=''): cv.string,
        vol.Required(CONF_FPING_INTERVAL, default=0): cv.positive_int,
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

def parse_arp_a_line(line):
    r = r'([a-zA-Z0-9_.-]+|\?) \((([0-9]+\.){3}[0-9]+)\) at (([0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2}|<[a-z]+>) .*'
    m = re.match(r, line)
    if not m:
        return None, None, None

    if m[1] == '?':
        hostname = None
    else:
        hostname = m[1]

    ipv4 = m[2]

    if m[4][0] == '<':
        mac = None
    else:
        mac = m[4]

    return hostname, ipv4, mac

class ArpDeviceScanner(DeviceScanner):
    """This class scans for devices using arp+ping."""

    exclude = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []
        self.fping_time = None

        self.hosts = config[CONF_HOSTS]
        self.exclude = config[CONF_EXCLUDE]
        minutes = config[CONF_HOME_INTERVAL]
        self._ping_timeout = config[CONF_PING_TIMEOUT]
        self._ping_incomplete = config[CONF_PING_INCOMPLETE]
        self._iface = config[CONF_IFACE]
        self.home_interval = timedelta(minutes=minutes)
        self.fping_interval = timedelta(seconds=config[CONF_FPING_INTERVAL])

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
        now = dt_util.now()
        if self.home_interval:
            boundary = now - self.home_interval
            for device in self.last_results:
                if device.last_update > boundary:
                    last_results.append(device)
                    last_macs.append(device.mac)

        if self.fping_interval and (self.fping_time is None or now > self.fping_time + self.fping_interval):
            ip_masks = []
            single_ips = []
            for mask in self.hosts:
                if '/' in mask:
                    ip_masks.append([ '-g', mask ])
                elif re.match(r'([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)', mask):
                    single_ips.append(mask)
            if len(single_ips):
                ip_masks.append(single_ips)
            for mask in ip_masks:
                cmd = [ 'fping', '-q', '-r', '0', '-t', str(int(self._ping_timeout * 1000)) ] + mask
                _LOGGER.debug('Running ' + ' '.join(cmd) + '...')
                try:
                    subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
                except Exception as e:
                    _LOGGER.error('Fail: ' + ' '.join(cmd) + ' resulted in ' + str(e))
            self.fping_time = now

        cmd = [ 'arp', '-a' ]
        if self._iface:
            cmd += [ '-i', self._iface ]
        _LOGGER.debug('Running ' + ' '.join(cmd) + '...')
        try:
            out, _ = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
        except Exception as e:
            _LOGGER.error('Fail: ' + ' '.join(cmd) + ' resulted in ' + str(e))
            return False

        for line in out.decode('utf-8').splitlines():
            # Format is: <hostname>|? (<ip>) at <mac> [<iftype>] on <iface>
            # The hostname is optional for us.  If we can't parse the IP the
            # entry is not useful to us.  If we can't parse the mac, it may
            # not have been cached yet so we'll still attempt a ping.
            hostname, ipv4, mac = parse_arp_a_line(line)

            if ipv4 is None or mac in last_macs:
                continue
            if mac is None and not self._ping_incomplete:
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
                _LOGGER.error('Fail: ' + ' '.join(cmd) + ' resulted in ' + str(e))
                continue

            # If we had no mac for this device, but it replied to the ping,
            # the ARP table will now have the mac cached.
            if mac is None:
                cmd = [ 'arp', '-a' ]
                if self._iface:
                    cmd += [ '-i', self._iface ]
                cmd += [ ipv4 ]
                _LOGGER.debug('Running ' + ' '.join(cmd) + '...')
                try:
                    out, _ = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
                except Exception as e:
                    _LOGGER.error('Fail: ' + ' '.join(cmd) + ' resulted in ' + str(e))
                    continue

                hostname, new_ip, mac = parse_arp_a_line(line)
                if new_ip != ipv4 or mac in last_macs or mac is None:
                    continue

            last_results.append(Device(mac.upper(), hostname, ipv4, now))

        self.last_results = last_results

        _LOGGER.debug("arp scan done")
        return True
