# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# verify if in the admin context
#

"""
Napalm driver for Cisco ASA.

Read https://napalm.readthedocs.io for more information.

Initiated from colsil / napalm-asa
"""

import copy
import re
import socket

from napalm.base.base import NetworkDriver
from napalm.base.helpers import mac
from napalm.base.helpers import (
    textfsm_extractor,
)
from napalm.base.netmiko_helpers import netmiko_args
from netaddr import IPAddress
from netmiko import ConnectHandler

from custom_napalm.helpers import GeneralDeploymentMode

HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"

IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX


class DeploymentMode(GeneralDeploymentMode):
    UNKNOWN = (0, None)
    STANDALONE = (1, "StandaloneOnboarding")

    HA = (400, "AsaHaOnboarding")
    HA_CONTEXT = (401, "AsaHaOnboarding")
    STANDALONE_CONTEXT = (402, "StandaloneOnboarding")


class BaxterASASSHDriver(NetworkDriver):
    """Napalm driver for Cisco ASA."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.candidate_config = None
        self.rollback_config = None

        self.dest_file_system = None
        self.context = None

        optional_args = copy.deepcopy(optional_args)

        if optional_args is None:
            optional_args = {}

        #_netmiko_open checks if driver needs to enter enable mode
        self.force_no_enable = optional_args.get("force_no_enable", False)

        self.netmiko_optional_args = netmiko_args(optional_args)

        self.context = optional_args.pop('context', None)
        # set secret to password if no secret is provided
        self.secret = optional_args.pop("secret", password)
        self.auto_rollback_on_error = optional_args.pop('auto_rollback_on_error', True)

        self.optional_args = optional_args

        self.failover_primary_ip = None
        self.failover_standby_ip = None
        self.login_context = None

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {
                'is_alive': False
            }
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def open(self):
        """Implementation of NAPALM method open."""
        device_type = "cisco_asa"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

        self.login_context = self._get_context()

        # Change Context to System
        self.device.send_command("changeto system")

        # if not self.dest_file_system:
        #     try:
        #         self.dest_file_system = self.device._autodetect_fs()
        #     except AttributeError:
        #         raise AttributeError("Netmiko _autodetect_fs not found please upgrade Netmiko or "
        #                              "specify dest_file_system in optional_args.")
        if self.context and self.context != 'system':
            self.device.send_command("changeto context " + self.context)

    def _get_context(self):
        show_context = self._send_command('show context')

        for line in show_context.splitlines():
            if line.startswith("*"):
                context = line.split()[0].replace('*', '').strip()
                return context

    def close(self):
        """Implementation of NAPALM method close."""
        self.device.disconnect()

    @staticmethod
    def _send_command_postprocess(output):
        """
        Keep same structure as for ios module but don't do anything for now
        """
        return output

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        output = ""
        if isinstance(command, list):
            for cmd in command:
                output = self.device.send_command(cmd)
                if "% Invalid" not in output:
                    break
        else:
            output = self.device.send_command(command)
        return self._send_command_postprocess(output)

    def get_facts(self, mate=False):
        vendor = u'Cisco'
        uptime = -1
        serial_number, fqdn, os_version, hostname, model = (
            u'Unknown', u'Unknown', u'Unknown', u'Unknown', u'Unknown')

        if mate:
            show_ver = self._send_command('failover exec mate show version')
            show_hostname = self._send_command('failover exec mate show hostname')
            show_fqdn = self._send_command('failover exec mate show hostname fqdn')
            show_inventory = self._send_command('failover exec mate show inventory')
            show_interfaces = self._send_command('failover exec mate show interface ip brief')
        else:
            show_ver = self._send_command('show version')
            show_hostname = self._send_command('show hostname')
            show_fqdn = self._send_command('show hostname fqdn')
            show_inventory = self._send_command('show inventory')
            show_interfaces = self._send_command('show interface ip brief')

        # Hostname and FQDN are returned by show commands without any other output
        hostname = show_hostname.strip()
        fqdn = show_fqdn.strip()

        # Parse show version command
        # Gather os version, uptime and serial number
        for line in show_ver.splitlines():
            if 'Cisco Adaptive Security Appliance Software Version' in line:
                os_version_match = re.match(
                    r"Cisco Adaptive Security Appliance Software Version (\S*)",
                    line
                )
                os_version = os_version_match.group(1)
            if hostname + ' up ' in line:
                _, uptime_str = line.split(' up ')
                uptime = self.parse_uptime(uptime_str)
            if "Serial Number: " in line:
                _, serial_number = line.split(' Number: ')
                serial_number = serial_number.strip()

        chassis_flag = False
        for line in show_inventory.splitlines():
            if "Name: \"Chassis\"" in line:
                chassis_flag = True
            if chassis_flag and "PID: " in line:
                match = re.search(r'PID: (\S*) .*', line)
                model = match.group(1)
                chassis_flag = False

        # Build interface list
        interface_list = []
        for line in show_interfaces.splitlines():
            interface_match = re.search(r'\S+\d+\/\d+\.?\d*', line)
            if interface_match:
                interface_list.append(interface_match.group(0))

        return {
            'uptime': uptime,
            'vendor': vendor,
            'os_version': os_version,
            'serial_number': serial_number,
            'model': model,
            'hostname': hostname,
            'fqdn': fqdn,
            'interface_list': interface_list
        }

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco Device.

        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes, seconds) = (0, 0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = re.split(r"(\d+ \S+)", uptime_str)
        for element in time_list:
            if re.search("year", element):
                years = int(element.split()[0])
            elif re.search("week", element):
                weeks = int(element.split()[0])
            elif re.search("day", element):
                days = int(element.split()[0])
            elif re.search("hour", element):
                hours = int(element.split()[0])
            elif re.search("min", element):
                minutes = int(element.split()[0])
            elif re.search("sec", element):
                seconds = int(element.split()[0])

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * 3600) + (minutes * 60) + (seconds)
        return uptime_sec

    def get_config(self, retrieve="all", full=False):
        configs = {"startup": "", "running": "", "candidate": ""}
        run_full = " all" if full else ""

        changed_context = False

        if self.context:
            previous_context = self._get_context()

            if self.context != previous_context:
                self._send_command("changeto context {self.context}")
                changed_context = True
        
        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            #output = re.sub(filter_pattern, "", output, flags=re.M)
            configs["startup"] = output.strip()

        if retrieve in ("running", "all"):
            command = "show running-config{}".format(run_full)
            output = self._send_command(command)
            #output = re.sub(filter_pattern, "", output, flags=re.M)
            configs["running"] = output.strip()

        if changed_context:
            self._send_command("changeto context {previous_context}")

        return configs

    def get_interfaces(self, mate=False):
        """
        Get interface details.
        last_flapped is not implemented
        Example Output:
        {   u'Management0/0': {   'description': u'N/A',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 1000},
        u'GigabitEthernet0/0': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 1000},
        u'GigabitEthernet0/1': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 1000}}
        """
        # default values.
        last_flapped = -1.0

        if mate:
            command = 'failover exec mate show interface'
        else:
            command = 'show interface'

        output = self._send_command(command)

        interface = description = mac_address = speed = speedformat = ''
        is_enabled = is_up = None

        interface_dict = {}
        for line in output.splitlines():

            interface_regex = \
                r"^Interface\s+(\S+?)\s+\"(\S*)\",\s+is\s+(.+?),\s+line\s+protocol\s+is\s+(\S+)"
            if re.search(interface_regex, line):
                interface_match = re.search(interface_regex, line)
                interface = interface_match.groups()[0]
                description = interface_match.groups()[1]
                status = interface_match.groups()[2]
                protocol = interface_match.groups()[3]

                if 'admin' in status:
                    is_enabled = False
                else:
                    is_enabled = True
                is_up = bool('up' in protocol)

            speed_regex = r"^\s+.+BW\s+(\d+)\s+([KMG]?b)"
            if re.search(speed_regex, line):
                speed_match = re.search(speed_regex, line)
                speed = speed_match.groups()[0]
                speedformat = speed_match.groups()[1]
                speed = float(speed)
                if speedformat.startswith('Kb'):
                    speed = speed / 1000.0
                elif speedformat.startswith('Gb'):
                    speed = speed * 1000
                speed = int(round(speed))

            vlan_regex = r"^\s+VLAN identifier"
            if re.search(vlan_regex, line):
                interface_dict[interface] = {'is_enabled': is_enabled, 'is_up': is_up,
                                             'description': description, 'mac_address': mac_address,
                                             'last_flapped': last_flapped, 'speed': speed}
                interface = description = mac_address = speed = speedformat = ''
                is_enabled = is_up = None

            mac_addr_regex = r"^\s+MAC\s+address\s+({})".format(MAC_REGEX)
            if re.search(mac_addr_regex, line):
                mac_addr_match = re.search(mac_addr_regex, line)
                mac_address = mac(mac_addr_match.groups()[0])

                if interface == '':
                    raise ValueError("Interface attributes were \
                                                  found without any known interface")
                if not isinstance(is_up, bool) or not isinstance(is_enabled, bool):
                    raise ValueError("Did not correctly find the interface status")

                interface_dict[interface] = {'is_enabled': is_enabled, 'is_up': is_up,
                                             'description': description, 'mac_address': mac_address,
                                             'last_flapped': last_flapped, 'speed': speed}
                interface = description = mac_address = speed = speedformat = ''
                is_enabled = is_up = None

        return interface_dict

    def get_interfaces_ip(self, mate=False, current=True, context=None):
        """
        Get interface ip details. (system_interfaces - intended during HA (not current))
        Returns a dict of dicts
        Example Output:
        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': 10}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        context_changed = False

        if self.login_context and not context:
            self.device.send_command("changeto context {context}".format(context=self.login_context))
            context_changed = True
        elif self.login_context and context:
            self.device.send_command("changeto context {context}".format(context=context))
            context_changed = True

        if mate:
            command = "failover exec mate show ip address"
        else:
            command = "show ip address"

        output = self._send_command(command)

        INTERNET_ADDRESS = r"(?P<interface>\S+)\s+(?P<name>\w+)?\s+(?P<ip>{})\s+(?P<netmask>{}).*".format(
            IPV4_ADDR_REGEX, IPV4_ADDR_REGEX)

        interfaces = {}
        current_found = False

        for line in output.splitlines():
            if len(line.strip()) == 0:
                continue

            # # Get only Configured IPs
            if 'Current IP Addresses:'.lower() in line.lower():
                current_found = True

            if current and not current_found:
                continue

            if not current and current_found:
                break

            m = re.match(INTERNET_ADDRESS, line)
            if m:
                _groupdict = m.groupdict()
                interface_name = _groupdict.get('interface')
                ip = _groupdict.get('ip')
                prefix = _groupdict.get('netmask')
                prefix = IPAddress(prefix).netmask_bits()

                if not all([interface_name, ip, prefix]):
                    continue

                if interface_name not in interfaces:
                    interfaces[interface_name] = {"ipv4": {}}
                interfaces[interface_name]['ipv4'].update({ip: {"prefix_length": int(prefix)}})

        # Exit to system / drivers context after getting results
        if context_changed:
            self.device.send_command("changeto system")

        return interfaces

    def get_show_inventory_structured(self, mate=False):
        if mate:
            command = "failover exec mate show inventory"
        else:
            command = "show inventory"

        raw_command_output = self._send_command(command)
        parsed_cisco_ios_show_inventory = textfsm_extractor(
            self, "cisco_asa_show_inventory", raw_command_output
        )

        return parsed_cisco_ios_show_inventory

    def get_show_version_structured(self, mate=False):
        if mate:
            command = "failover exec mate show version"
        else:
            command = "show version"

        raw_command_output = self._send_command(command)
        parsed_cisco_ios_show_version = textfsm_extractor(
            self, "cisco_asa_show_version", raw_command_output
        )

        return parsed_cisco_ios_show_version

    def get_show_failover_structured(self, mate=False):
        if mate:
            command = "failover exec mate show failover"
        else:
            command = "show failover"

        raw_command_output = self._send_command(command)
        parsed_cisco_ios_show_failover = textfsm_extractor(
            self, "cisco_asa_show_failover", raw_command_output
        )

        return parsed_cisco_ios_show_failover

    def get_device_deployment_mode(self):
        asa_options = []
        show_ver = self._send_command('show version')

        for line in show_ver.splitlines():
            # Raise if FirePower
            # if line.strip().startswith('Firepower Extensible Operating System Version'):
            #     raise NotImplementedError('Firepower not supported')
            # Check if first line of show version ends with <context> to identify contexts
            if line.strip().startswith('Cisco Adaptive Security') \
                    and (line.strip().endswith('<context>') or line.strip().endswith('<system>')):
                asa_options.append("context")

            # Check for failover
            if line.startswith('failover cluster'):
                asa_options.append("ha")

        if 'ha' in asa_options and 'context' in asa_options:
            return DeploymentMode.HA_CONTEXT
        elif 'ha' in asa_options and 'context' not in asa_options:
            return DeploymentMode.HA
        elif 'ha' not in asa_options and 'context' in asa_options:
            return DeploymentMode.STANDALONE_CONTEXT
        else:
            return DeploymentMode.STANDALONE

    def _set_mgmt_details(self):
        _current_ips = self.get_interfaces_ip(mate=False, current=True, context=self.login_context)
        _current_ips_on_mate = self.get_interfaces_ip(mate=True, current=True, context=self.login_context)
        _system_ips = self.get_interfaces_ip(mate=False, current=False, context=self.login_context)

        _management_interface = self.get_mgmt_interface_name(ip_ifs=_current_ips)

        self.failover_primary_ip = list(_system_ips[_management_interface]['ipv4'].keys())[0]

        # If Primary Device operates in active mode:
        if _current_ips == _system_ips:
            self.failover_standby_ip = list(_current_ips_on_mate[_management_interface]['ipv4'].keys())[0]
        # If Primary Device is not in active mode:
        else:
            self.failover_standby_ip = self.hostname

    def get_mgmt_interface_name(self, ip_ifs):
        """
        Extracts management interface name

        Inputs: ip_ifs - structured as in custom_napalm's device.get_interfaces_ip()

        Returns: mgmt_ifname
        """
        for if_name in ip_ifs:
            if self.hostname in ip_ifs[if_name].get('ipv4', {}):
                return if_name
            elif self.hostname in ip_ifs[if_name].get('ipv6', {}):
                return if_name

        return None

    def get_multi_device_structured_inventory(self, deployment_mode):
        """
        Structured data for switch stacks:
        [ {
            'position': int(),
            'model': str(),
            'serial': str(),
        } , { } , ... ]

        :return:
        """
        if deployment_mode in [DeploymentMode.UNKNOWN, DeploymentMode.STANDALONE]:
            raise NotImplementedError("Function does not support this deployment mode")

        failover_status = self.get_show_failover_structured()

        if len(failover_status) != 1:
            raise ValueError("Invalid failover information")
        if failover_status[0]['state'].lower() != 'on':
            raise ValueError("Failover not in 'on' state")
        if failover_status[0]['lan_intf_state'].lower() != 'up':
            raise ValueError("Failover interface is not up")

        failover_role = failover_status[0]['role'].lower().strip()

        chassis_primary = None
        chassis_secondary = None

        if failover_role == 'primary':
            primary_show_inventory = self.get_show_inventory_structured(mate=False)
            secondary_show_inventory = self.get_show_inventory_structured(mate=True)

            chassis_primary = list(filter(lambda i: i['name'] == 'Chassis', primary_show_inventory))
            chassis_secondary = list(filter(lambda i: i['name'] == 'Chassis', secondary_show_inventory))

            if len(chassis_primary) != 1 or len(chassis_secondary) != 1:
                raise ValueError("Invalid chassis information (prim)")

        elif failover_role == 'secondary':
            primary_show_inventory = self.get_show_inventory_structured(mate=True)
            secondary_show_inventory = self.get_show_inventory_structured(mate=False)

            chassis_primary = list(filter(lambda i: i['name'] == 'Chassis', primary_show_inventory))
            chassis_secondary = list(filter(lambda i: i['name'] == 'Chassis', secondary_show_inventory))

            if len(chassis_primary) != 1 or len(chassis_secondary) != 1:
                raise ValueError("Invalid chassis information (sec)")

        if not chassis_primary or not chassis_secondary:
            raise ValueError("Invalid chassis information (gen)")

        self._set_mgmt_details()

        structured_data = [
            {
                'position': 1,
                'model': chassis_primary[0]['pid'],
                'serial': chassis_primary[0]['sn'],
                'ipaddr': self.failover_primary_ip
            },
            {
                'position': 2,
                'model': chassis_secondary[0]['pid'],
                'serial': chassis_secondary[0]['sn'],
                'ipaddr': self.failover_standby_ip
            },
        ]

        return structured_data
