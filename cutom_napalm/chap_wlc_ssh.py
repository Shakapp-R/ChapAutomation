from netaddr import cidr_abbrev_to_verbose
from netaddr import IPAddress
import re
import socket

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionClosedException
from napalm.base.helpers import textfsm_extractor
from napalm.base.netmiko_helpers import netmiko_args

from netmiko import ConnectHandler

from custom_napalm.helpers import GeneralDeploymentMode

HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


class DeploymentMode(GeneralDeploymentMode):
    UNKNOWN = (0, None)
    STANDALONE = (502, "WLCStandaloneOnboarding")
    HA_PAIR_PRIMARY = (500, "WlcHaOnboarding")
    HA_PAIR_SECONDARY = (501, "WlcHaOnboarding")


class BaxterWLCSSHDriver(NetworkDriver):
    """Napalm driver for Cisco WLC."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""

        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        #_netmiko_open checks if driver needs to enter enable mode
        self.force_no_enable = optional_args.get("force_no_enable", True)
        
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("banner_timeout", 40)
        self.netmiko_optional_args.setdefault("session_timeout", 60)
        self.netmiko_optional_args.setdefault("auth_timeout", 40)

        self.get_interfaces_ip_on_open = False
        self.get_interfaces_ip_on_open_result = None

    def _get_show_ap_summary(self):
        command = "show ap summary"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_ap_summary = textfsm_extractor(
            self, "cisco_wlc_show_ap_summary", raw_command_output
        )
        return parsed_cisco_wlc_show_ap_summary

    def _get_show_ap_config_general(self, hostname):
        command = f"show ap config general {hostname}"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_ap_config_general = textfsm_extractor(
            self, "cisco_wlc_show_ap_config_general", raw_command_output
        )
        return parsed_cisco_wlc_show_ap_config_general

    def _get_show_ap_inventory_all(self):
        command = f"show ap inventory all"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_ap_inventory_all = textfsm_extractor(
            self, "cisco_wlc_show_ap_inventory_all", raw_command_output
        )

        result_dict = {}
        for row in parsed_cisco_wlc_show_ap_inventory_all:
            result_dict[row.pop("hostname")] = row

        return result_dict

    def _get_show_ap_stats_ethernet_summary(self):
        command = f"show ap stats ethernet summary"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_ap_stats_ethernet_summary = textfsm_extractor(
            self, "cisco_wlc_show_ap_stats_ethernet_summary", raw_command_output
        )

        result_dict = {}
        for row in parsed_cisco_wlc_show_ap_stats_ethernet_summary:
            ap = row["ap"]
            del row["ap"]
            if ap not in result_dict.keys():
                result_dict[ap] = [row]
            else:
                result_dict[ap] += [row]

        return result_dict

    @staticmethod
    def _generate_hostname(mac):
        mac_num_list = mac.split(":")
        hostname = []
        for index in range(3):
            hostname.append(f"{mac_num_list[2*index]}{mac_num_list[2*index+1]}")
        return f"AP{'.'.join(hostname)}"

    def get_ap_facts(self):
        """
        This method will return facts for the access-points connected to this wlc
        The result will be a list of dictionaries, where each item in the list represents an access-point
        """
        result = []

        # Get the AP summary and their interfaces list
        parsed_show_ap_summary = self._get_show_ap_summary()
        parsed_show_ap_stats_ethernet_summary = \
            self._get_show_ap_stats_ethernet_summary()
        parsed_show_ap_inventory_all = self._get_show_ap_inventory_all()

        for item in parsed_show_ap_summary:
            mac = item.get("mac", "")
            new_ap_name = BaxterWLCSSHDriver._generate_hostname(mac)
            configured_ap_name = item.get("ap_name", "")

            # Get general config details about the AP
            uptime = 0
            parsed_show_ap_inventory = \
                parsed_show_ap_inventory_all.get(configured_ap_name, {"sn": ""})
            serial_number = parsed_show_ap_inventory.get("sn", "")
            interface_list = \
                parsed_show_ap_stats_ethernet_summary.get(configured_ap_name, [])

            result.append(
                {
                    "uptime": uptime,
                    "vendor": "Cisco",
                    "serial_number": serial_number,
                    "model": item.get("ap_model", ""),
                    "mac": mac,
                    "hostname": new_ap_name,
                    "configured_hostname": configured_ap_name,
                    "fqdn": new_ap_name,
                    "interface_list": interface_list
                }
            )

        return result

    def get_show_sysinfo_structured(self):
        command = "show sysinfo"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_sysinfo = textfsm_extractor(
            self, "cisco_wlc_show_sysinfo", raw_command_output
        )
        return parsed_cisco_wlc_show_sysinfo

    def get_show_inventory_structured(self):
        command = "show inventory"
        raw_command_output = self._send_command(command)
        parsed_cisco_wlc_show_sysinfo = textfsm_extractor(
            self, "cisco_wlc_show_inventory", raw_command_output
        )
        return parsed_cisco_wlc_show_sysinfo

    def get_show_redundancy_summary(self):
        command = "show redundancy summary"
        raw_command_output = self._send_command(command)
        parsed_show_redundancy_summary = textfsm_extractor(
            self, "cisco_wlc_show_redundancy_summary", raw_command_output
        )
        return parsed_show_redundancy_summary

    def get_show_redundancy_detail(self):
        command = "show redundancy detail"
        raw_command_output = self._send_command(command)
        parsed_show_redundancy_detail = textfsm_extractor(
            self, "cisco_wlc_show_redundancy_detail", raw_command_output
        )
        return parsed_show_redundancy_detail

    def get_device_deployment_mode(self):
        """
        takes in : parsed_redundancy_summary, parsed show sysinfo

        :return: $deployment_mode, ie "standalone", "unknown", "ha_pair_primary", "ha_pair_secondary"
        """
        parsed_show_redundancy_summary = self.get_show_redundancy_summary()

        '''
        Looks for HA information in show redundancy summary
        '''
        if parsed_show_redundancy_summary == []:
            #2100 series WLCs do not support show redundancy summary, or HA pairs
            return DeploymentMode.STANDALONE
        for redundancy_element in parsed_show_redundancy_summary:
            if redundancy_element['non_ha_pair'].lower().strip() == "primary" or redundancy_element['non_ha_pair'].lower().strip() == "secondary":
                return DeploymentMode.STANDALONE
            elif redundancy_element['local_state'].lower().strip() == "active":
                if redundancy_element['peer_state'].lower().strip() != 'n/a':
                    return DeploymentMode.HA_PAIR_PRIMARY
                elif redundancy_element['peer_state'].lower().strip() == 'n/a':
                    return DeploymentMode.STANDALONE
            elif redundancy_element['local_state'].lower().strip() == "standby hot":
                if redundancy_element['peer_state'].lower().strip() != 'n/a':
                    return DeploymentMode.HA_PAIR_SECONDARY
                elif redundancy_element['peer_state'].lower().strip() == 'n/a':
                    return DeploymentMode.STANDALONE
            else:
                return DeploymentMode.UNKNOWN

    def get_multi_device_structured_inventory(self, deployment_mode):
        """
        Structured data for switch stacks:
        [ {
            'position': int(),
            'model': str(),
            'serial': str(),
        } , { } , ... ]

        :param deployment_mode:
        :param parsed_cisco_ios_show_inventory:
        :return: structured inventory
        """
        if deployment_mode in [DeploymentMode.UNKNOWN, DeploymentMode.STANDALONE]:
            raise NotImplementedError("Function does not support this deployment mode")
    
        parsed_show_redundancy_summary = self.get_show_redundancy_summary()
        parsed_show_redundancy_detail = self.get_show_redundancy_detail()

        primary_wlc = {}
        secondary_wlc = {}

        if parsed_show_redundancy_summary[0]['local_state'].lower().strip() == "active":
            parsed_cisco_wlc_show_inventory = self.get_show_inventory_structured()
            primary_wlc = {
                'position': 1,
                'model': parsed_cisco_wlc_show_inventory[0]["pid"],
                'serial': parsed_cisco_wlc_show_inventory[0]['sn'],
                "ipaddr": parsed_show_redundancy_detail[0]["redundancy_mgmt_ip"]
            }
            secondary_wlc = {
                'position': 2,
                'model': parsed_cisco_wlc_show_inventory[0]["pid"],
                'serial': '',
                "ipaddr": parsed_show_redundancy_detail[0]["peer_redundancy_mgmt_ip"]
            }
        elif parsed_show_redundancy_summary[0]['local_state'].lower().strip() == "standby hot":
            # it is in standby
            parsed_cisco_wlc_show_inventory = self.get_show_inventory_structured()
            primary_wlc = {
                'position': 1,
                'model': parsed_cisco_wlc_show_inventory[0]["pid"],
                'serial': '',
                "ipaddr": parsed_show_redundancy_detail[0]["peer_redundancy_mgmt_ip"]
            }
            secondary_wlc = {
                'position': 2,
                'model': parsed_cisco_wlc_show_inventory[0]["pid"],
                'serial': parsed_cisco_wlc_show_inventory[0]['sn'],
                "ipaddr": parsed_show_redundancy_detail[0]["redundancy_mgmt_ip"]
            }
        else:
            raise ValueError("Invalid WLC HA Pair information")

        structured_data = [primary_wlc, secondary_wlc]
        return structured_data

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self.device.write_channel(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {"is_alive": False}
        return {"is_alive": self.device.remote_conn.transport.is_active()}

    def open(self):
        """Implementation of NAPALM method open."""
        device_type = "cisco_wlc_ssh"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""
        self._netmiko_close()

    @staticmethod
    def _send_command_postprocess(output):
        """
        Keep same structure as for ios module but don't do anything for now
        """
        return output.strip()

    def _send_command(self, command, **kwargs):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        output = ""
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd, **kwargs)
                    if "Invalid usage." not in output:
                        break
            else:
                output = self.device.send_command(command, **kwargs)
            if isinstance(output, str):
                return self._send_command_postprocess(output)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.
        Example input:
        ['show clock', 'show calendar']
        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands")

        for command in commands:
            output = self._send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.
        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes, secs) = (0, 0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(",")
        for element in time_list:
            if re.search("years", element):
                years = int(element.split()[0])
            elif re.search("weeks", element):
                weeks = int(element.split()[0])
            elif re.search("days", element):
                days = int(element.split()[0])
            elif re.search("hrs", element):
                hours = int(element.split()[0])
            elif re.search("mins", element):
                minutes = int(element.split()[0])
            elif re.search("secs", element):
                secs = int(element.split()[0])

        uptime_sec = (
            (years * YEAR_SECONDS)
            + (weeks * WEEK_SECONDS)
            + (days * DAY_SECONDS)
            + (hours * 3600)
            + (minutes * 60)
            + (secs)
        )
        return uptime_sec

    def get_interfaces(self):
        """
        {'1': {'description': '',
            'is_enabled': True,
            'is_up': True,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': '1000'},
        '2': {'description': '',
            'is_enabled': True,
            'is_up': True,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': '1000'},
        '3': {'description': '',
            'is_enabled': True,
            'is_up': False,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': ''},
        'int-office': {'description': '',
            'is_enabled': True,
            'is_up': True,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': '1000'},
        'management': {'description': '',
            'is_enabled': True,
            'is_up': True,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': '1000'},
        'virtual': {'description': '',
            'is_enabled': True,
            'is_up': True,
            'last_flapped': '-1',
            'mac_address': 'e0:ac:f1:xx:xx:xx',
            'mtu': '1500',
            'speed': '1000'}}
        """
        show_interface_summary = self._send_command("show interface summary")
        # show_port_vlan = self._send_command("show port vlan").split("\n")
        show_port_summary = self._send_command("show port summary")
        show_port_detailed = self._send_command("show port detailed-info")

        interfaces = {}

        interface_summary = textfsm_extractor(
            self, "cisco_wlc_show_interface_summary", show_interface_summary
        )
        port_detailed = textfsm_extractor(
            self, "cisco_wlc_show_port_detailed-info", show_port_detailed
        )
        port_summary = textfsm_extractor(
            self, "cisco_wlc_show_port_summary", show_port_summary
        )

        mac = ''
        mtu = ''
        for entry in port_summary:
            for pd in port_detailed:
                if pd["name"] == entry["name"]:
                    mtu = pd["mtu"]
                    mac = pd["mac"]

            interfaces[entry["name"]] = {
                "is_up": entry["status"] == "Up",
                "is_enabled": entry["admin_mode"] == "Enable",
                "description": "",
                "last_flapped": "-1",
                "mac_address": mac.replace("-", ":"),
                "mtu": mtu,
                "speed": entry["speed"],
            }

        for entry in interface_summary:

            speed = ""
            mtu = ""
            mac = ""
            interface = entry["name"]

            show_interface_detailed = self._send_command(
                "show interface detailed {}".format(interface)
            )

            interface_detailed = textfsm_extractor(
                self, "cisco_wlc_show_interface_detailed", show_interface_detailed
            )[0]

            is_up = False
            for port in port_summary:
                if port["status"] == "Up":
                    is_up = True

                    for p in port_detailed:
                        if p["name"] == port["name"]:
                            mtu = p["mtu"]

                    speed = port["speed"]
                    break

            is_enabled = False
            for port in port_summary:
                if port["admin_mode"] == "Enable":
                    is_enabled = True
                    break

            interfaces[interface] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": "",
                "last_flapped": "-1",
                "mac_address": interface_detailed["mac"],
                "speed": speed,
                "mtu": mtu,
            }

        return interfaces

    def get_interfaces_ip(self):
        """
        Get interface ip details.
        Returns a dict of dicts
        Example Output:
        {'ap-manager': {'ipv4': {'10.36.x.x': {'prefix_length': 24}}},
         'int-1': {'ipv4': {'10.36.x.x': {'prefix_length': 24}}},
         'int-2': {'ipv4': {'10.36.x.x': {'prefix_length': 24}}},
         'int-3': {'ipv4': {'10.36.x.x': {'prefix_length': 24}}},
         'int-4': {'ipv4': {'10.36.x.x': {'prefix_length': 24}}},
         'management': {'ipv4': {'10.36.x.x': {'prefix_length': 25}},
         'virtual': {'ipv4': '1.1.1.1'}}
        """

        show_interface_summary = self._send_command("show interface summary")
        interface_summary = textfsm_extractor(
            self, "cisco_wlc_show_interface_summary", show_interface_summary
        )

        interfaces_ip = {}

        for interface in interface_summary:
            output = self._send_command(
                "show interface detailed {}".format(interface["name"])
            )
            interface_detailed = textfsm_extractor(
                self, "cisco_wlc_show_interface_detailed", output
            )[0]

            # virtual interface does not have a mask configured
            if interface_detailed["name"] == "virtual":
                interface_detailed["mask"] = "255.255.255.255"

            # 0.0.0.0/32
            if interface_detailed["ip"] == '0.0.0.0':
                interface_detailed["mask"] = "255.255.255.255"

            # giving classfull masks to interfaces with unknown masks
            if interface_detailed["mask"] == '':
                prefix_length = cidr_abbrev_to_verbose(interface_detailed["ip"])[-2:]
                if prefix_length == "/8":
                    interface_detailed["mask"] = "255.0.0.0"
                elif prefix_length == "16":
                    interface_detailed["mask"] = "255.255.0.0"
                else:
                    interface_detailed["mask"] = "255.255.255.0"

            prefix_len = IPAddress(interface_detailed["mask"]).netmask_bits()
            ip = {"ipv4": {interface_detailed["ip"]: {"prefix_length": prefix_len}}}
            interfaces_ip[interface["name"]] = ip

        return interfaces_ip

    def get_facts(self):
        """
        Returns a dictionary containing the following information:
        uptime: Uptime of the device in seconds.
        vendor: Manufacturer of the device.
        serial_number: Serial number of the device.
        model: Device model.
        hostname: Hostname of the device.
        FQDN: Fully qualified domain name of the device
        interfaces: list of interaces of the WLC
        os_version: Operating system version
        """
        vendor = u"Cisco"

        serial_number, model = (u"Unknown", u"Unknown")

        show_sysinfo = self.get_show_sysinfo_structured()
        show_inventory = self.get_show_inventory_structured()

        interfaces = self.get_interfaces()

        serial_number = show_inventory[0]["sn"]
        model = show_inventory[0]["pid"]
        uptime = self.parse_uptime(show_sysinfo[0]["system_up_time"])

        os_version = show_sysinfo[0]["product_version"]

        return {
            "uptime": uptime,
            "vendor": vendor,
            "os_version": os_version,
            "serial_number": serial_number,
            "model": model,
            "hostname": show_sysinfo[0]["system_name"],
            "fqdn": show_sysinfo[0]["system_name"],
            "interfaces": interfaces
        }
