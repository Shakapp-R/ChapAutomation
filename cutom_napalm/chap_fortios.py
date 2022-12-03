from netaddr import IPAddress, IPNetwork

from fortiosapi import FortiOSAPI
from napalm.base.base import NetworkDriver

from custom_napalm.helpers import GeneralDeploymentMode


class DeploymentMode(GeneralDeploymentMode):
    UNKNOWN = (0, None)
    STANDALONE = (1, "StandaloneOnboarding")
    HA = (600, "FortiOSHAOnboarding")


class BaxterFortiOSDriver(NetworkDriver):
    """ NAPALM driver for Fortinet devices running FortiOS"""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """ FortiOS NAPALM driver Constructor """

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        optional_args = optional_args or {}

        self.vdom = optional_args.get("vdom", None)
        # TODO enable SSL verification by default
        self.ssl_verify = optional_args.get("ssl_verify", False)
        self.port = optional_args.get("port", 443)
        self.device = FortiOSAPI()

    def open(self):
        """ Implementation of NAPALM open method """
        self.device.login(f"{self.hostname}:{self.port}", self.username, self.password, verify=self.ssl_verify)

    def get_facts(self):
        """ Returns a dictionary containing the following information about the device: """

        # upime API endpoint: monitor, system/time
        # vendor Fortinet
        # hostname, os_version, serial number API endpoint: config, system/global
        # interface list API endpoint: config, system/interface

        uptime = self.device.monitor("system", "time", vdom=self.vdom)["results"]["time"]
        model = self.device.monitor("system", "firmware", vdom=self.vdom)["results"]["current"]["platform-id"]

        system_global = self.device.get("system", "global", vdom=self.vdom) # HTTP GET request to system/global config endpoint
        hostname = system_global["results"]["hostname"]
        os_version = system_global["version"]
        serial = system_global["serial"]

        system_interface = self.device.get("system", "interface", vdom=self.vdom)

        interface_list = []
        for interface in system_interface["results"]:
            interface_list.append(interface["name"])

        facts = {
            "uptime": uptime,
            "vendor": u"Fortinet",
            "model": model,
            "hostname": hostname,
            "os_version": os_version,
            "serial_number": serial,
            "interface_list": interface_list
        }
        return facts

    def get_interfaces(self):
        """ information about interfaces on the device """

        system_interfaces = self.device.get("system", "interface", vdom=self.vdom)["results"]
        system_available_interfaces = self.device.monitor("system", "available-interfaces", vdom="*")
        interfaces_dict = {}

        system_interfaces = { interface["name"]: interface for interface in system_interfaces }

        for vdom in system_available_interfaces:
            for interface in vdom["results"]:
                system_interface = system_interfaces.get(interface["name"], {})
                interfaces_dict[interface["name"]] = {
                    "is_up": interface.get("status", "").lower() == "up",
                    "is_enabled": interface.get("status", "").lower() == "up",
                    "description": system_interface.get("description", ""),
                    "last_flapped": -1.0,
                    "speed": interface.get("speed", system_interface.get("speed", "")),
                    "mtu": system_interface.get("mtu"),
                    "mac_address": interface.get("mac_address", system_interface.get("macaddr", ""))
                }

        return interfaces_dict

    def get_interfaces_ip(self):
        """ Information of IP addresses assigned to interfaces on the device """

        system_interface = self.device.get("system", "interface", vdom=self.vdom)
        interfaces_dict = {}

        for interface in system_interface["results"]:
            ipv4_addr, netmask = interface["ip"].split()
            ipv6_addr = interface["ipv6"]["ip6-address"]
            # IPv6 addresses need to be parsed for mask length properly
            prefix_length_ipv4 = IPAddress(netmask).netmask_bits()
            prefix_length_ipv6 = IPNetwork(ipv6_addr).prefixlen
            interfaces_dict[interface["name"]] = {
                u'ipv4': {
                    ipv4_addr: {
                        "prefix_length": prefix_length_ipv4
                    }
                },
                u'ipv6': {
                    ipv6_addr: {
                        "prefix_length": prefix_length_ipv6
                    }
                }
            }

        return interfaces_dict

    def get_device_deployment_mode(self):
        """ Return deployment mode of the device """

        system_ha = self.device.get("system", "ha", vdom=self.vdom)
        if system_ha["results"]["mode"] == "a-p":
            return DeploymentMode.HA
        elif system_ha["results"]["mode"] == "a-a":
            return NotImplementedError("Active-active failover mode not supported")
        elif system_ha["results"]["mode"] == "standalone":
            return DeploymentMode.STANDALONE

        return DeploymentMode.UNKNOWN

    def get_multi_device_structured_inventory(self, deployment_mode):
        """ Returns a list of dicts representing a redundancy structure like an HA pair """

        if not deployment_mode == DeploymentMode.HA:
            return NotImplementedError("Function does not support this deployment mode")

        system_ha_checksums = self.device.monitor("system", "ha-checksums", vdom=self.vdom) # list of dicts informing whether devcice is master or secondary device

        if len(system_ha_checksums["results"]) == 1:
            raise ValueError("Device in invalid failover state ")

        multi_device_data = []

        model = self.device.monitor("system", "firmware", vdom=self.vdom)["results"]["current"]["platform-id"]
        
        for element in system_ha_checksums["results"]:
            if element["is_manage_master"] == 1:
                item = {
                    "position": 1,
                    "model": model,
                    "serial": element["serial_no"]
                }
            elif element["is_manage_master"] == 0:
                item = {
                    "position": 2,
                    "model": model,
                    "serial": element["serial_no"]
                }
            multi_device_data.append(item)

        return multi_device_data
