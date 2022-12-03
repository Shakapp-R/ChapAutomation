import re
from typing import AnyStr, List, Match, Optional

from napalm.base.helpers import (  # type: ignore
    textfsm_extractor,
)
from napalm.ios.ios import IOSDriver  # type: ignore
from netutils.mac import mac_to_format  # type: ignore

from custom_napalm.helpers import GeneralDeploymentMode


class DeploymentMode(GeneralDeploymentMode):
    """Driver Specific Deployment Mode Class"""

    UNKNOWN = (0, None)
    STANDALONE = (1, "StandaloneOnboarding")

    """
    C3750 stacks are recognized in a different way than c38 or c93.

    It might be IOS vs IOS-XE recognition, but so far we have not
    identified other cases to prove the IOS/IOS-XE logic and
    decided to use accurate, model-specific logic.
    """
    C3750_STACK = (100, "StackOnboarding")
    C38XX_STACK = (101, "StackOnboarding")
    C93XX_STACK = (102, "StackOnboarding")
    C2960_STACK = (103, "StackOnboarding")
    C95XX_STACK = (104, "StackOnboarding")
    C92XX_STACK = (105, "StackOnboarding")

    VSS = (200, "VssOnboarding")

    C9800_STANDALONE = (201, "WLCStandaloneOnboarding")
    C9800_HA = (202, "IOSWLCHAOnboarding")


class BaxterIOSDriver(IOSDriver):
    """Custom NAPALM Cisco IOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super(BaxterIOSDriver, self).__init__(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )

    @staticmethod
    def get_standardized_pid(pid: str) -> str:
        """
        Fixes and standardizes inconsistencies that occur in IOS:

        - model might be different depending on IOS software version
        - model might have different naming convention on switches

        """
        if pid.endswith("-S") or pid.endswith("-L"):
            return pid[:-2]

        return pid

    def get_lcm_software(self) -> str:
        """
        Getter to get the software release version for Nautobot's nautobot_device_lifecycle_mgmt plugin.

        Returns string.
        """
        _ver: list = self.get_show_version_structured()
        try:
            return _ver[0]["version"]
        except (TypeError, IndexError, KeyError):
            return "Unknown"

    def get_show_version_structured(self) -> list:
        command: str = "show version"
        raw_command_output: str = self._send_command(command)
        parsed_cisco_ios_show_version: list = textfsm_extractor(
            self, "cisco_ios_show_version", raw_command_output
        )

        return parsed_cisco_ios_show_version

    def get_show_inventory_structured(self) -> list:
        command: str = "show inventory"
        raw_command_output: str = self._send_command(command)
        parsed_cisco_ios_show_inventory: list = textfsm_extractor(
            self, "cisco_ios_show_inventory", raw_command_output
        )

        return parsed_cisco_ios_show_inventory

    def get_inventory(self) -> list:
        """
        Wrapper to get_show_inventory_structured
        """
        return self.get_show_inventory_structured()

    def get_show_redundancy(self) -> list:
        """
        Get `show redundancy` output from IOS-XE wireless controller
        """
        command: str = "show redundancy"
        raw_command_output: str = self._send_command(command)
        parsed_cisco_ios_xe_show_redundancy: list = textfsm_extractor(
            self, "cisco_ios_xe_show_redundancy", raw_command_output
        )

        return parsed_cisco_ios_xe_show_redundancy

    def get_show_chassis(self) -> list:
        """
        Get `show chassis` output from IOS-XE wireless controller
        """
        command: str = "show chassis"
        raw_command_output: str = self._send_command(command)
        parsed_cisco_ios_xe_show_chassis: list = textfsm_extractor(
            self, "cisco_ios_xe_show_chassis", raw_command_output
        )

        return parsed_cisco_ios_xe_show_chassis

    def get_show_ap_config_general(self) -> list:
        """
        Get `show ap config general` from IOS-XE wireless controller
        """
        command: str = "show ap config general"
        # WLC could be managing a lot of APs (100+)
        # And in such cases the output would be lengthy.
        # here the `send_command` Netmiko method would timeout.
        # Using `send_command_timing` to wait for the device to give all info.
        # TODO: in netmiko 4.x can use `read_timeout_override` to increase the read timeout for `send_command`
        # https://github.com/ktbyers/netmiko/issues/2796
        raw_command_output: str = self.device.send_command_timing(command)
        parsed_cisco_ios_xe_show_ap_config_general: list = textfsm_extractor(
            self, "cisco_ios_xe_show_ap_config_general", raw_command_output
        )

        return parsed_cisco_ios_xe_show_ap_config_general

    def get_ap_facts(self) -> list:
        """
        Get facts about access points managed by Catalyst 9800 wireless controllers
        """
        result: list = []

        parsed_show_ap_config_general: list = self.get_show_ap_config_general()

        for ap in parsed_show_ap_config_general:
            # this ensures the generated AP name is in MMMM.MMSS.SSSS format
            # generated name to be used if configured AP name is not compliant
            generated_ap_name: str = (
                f"AP{mac_to_format(ap['mac'], frmt='MAC_DOT_FOUR')}"
            )

            # currently the access points being configured with the C9800 devices
            # are the 9120 and the 2800 series APs
            # In Nautobot we look to model them with 1 GigE interface- which connects to the access switch
            # there is no direct CLI command on the WLC to find the AP interfaces.
            ap_interface_list: List[dict] = [
                {
                    "int_name": "GigabitEthernet0",
                    "speed": "1000",
                }
            ]

            result.append(
                {
                    "uptime": 0,
                    "vendor": "Cisco",
                    "serial_number": ap["sn"],
                    "model": ap["ap_model"],
                    "mac": ap["mac"],
                    "configured_hostname": ap["ap_name"],
                    "hostname": generated_ap_name,  # AireOS WLC controlled APs use auto generated hostnames if configured hostname is not compliant
                    "interface_list": ap_interface_list,
                }
            )

        return result

    def get_device_deployment_mode(self) -> DeploymentMode:
        """
        takes in : parsed_inventory, parsed show version

        :return: $deployment_mode, ie "standalone", "c38xx Stack", etc
        """
        parsed_cisco_ios_show_inventory: list = self.get_show_inventory_structured()
        parsed_cisco_ios_show_version: list = self.get_show_version_structured()

        # output validation
        if len(parsed_cisco_ios_show_version) != 1:
            raise ValueError("Invalid length of parsed_showed_version")

        """
            Look for Stack information in show inventory

            IOS-XE (at least c38 or c93 so far) stacks are identified if
            special strings indicating "Stack" appears in the name of inventory
            element. It is the most accurate indication across different models
            and platforms of Cisco, so is placed first in the code.
        """
        for inventory_element in parsed_cisco_ios_show_inventory:
            # c38xx Stacks
            if "c38xx Stack".lower() in inventory_element.get("name", "").lower():
                return DeploymentMode.C38XX_STACK
            # c38xx Stacks on ~2013 IOS software shows "c3xxx"
            elif "c3xxx Stack".lower() in inventory_element.get(
                "name", ""
            ).lower() and inventory_element.get("pid", "").lower().startswith(
                "ws-c3850-"
            ):
                return DeploymentMode.C38XX_STACK
            # c93xx Stacks
            elif "c93xx Stack".lower() in inventory_element.get("name", "").lower():
                return DeploymentMode.C93XX_STACK
            # c95xx Stack
            elif "c95xx Stack".lower() in inventory_element.get("name", "").lower():
                return DeploymentMode.C95XX_STACK
            # c92xx Stack
            elif "c92xx Stack".lower() in inventory_element.get("name", "").lower():
                return DeploymentMode.C92XX_STACK
        """
            Look for Stack information in show version

            2960 & 3750 Stacks are identified based on the show version information.
            If show version indicates more than a single hardware device,
            and if all of them have $modelname string dep. mode is recognized.
        """
        switch_hardware: list = parsed_cisco_ios_show_version[0].get("hardware", [])

        if len(switch_hardware) > 1:
            if all("C3750" in x for x in switch_hardware):
                return DeploymentMode.C3750_STACK
            elif all("C2960X" in x for x in switch_hardware):
                return DeploymentMode.C2960_STACK
            else:
                return DeploymentMode.UNKNOWN

        """
            Checking for a Catalyst 9800 IOS-XE based wireless controller

            In the case of this wireless controller, it can be in a standalone or HA setup.
        """

        if all("C9800" in x for x in switch_hardware):
            # this is a cat9800 wireless controller running IOS-XE
            # need a separate case here as there are 2 possible deployment modes
            # and inventory is not a reliable representation of the intended/configured state

            # get chassis members list
            switch_chassis: list = self.get_show_chassis()

            if any(
                member.get("chassis_member_current_state", "").lower().strip()
                != "ready"
                for member in switch_chassis
            ):
                raise ValueError(
                    "C9800 WLC chassis state is not ready - cannot onboard the chassis"
                )

            # if we have reached here, we know we can find info about device(s) in chassis
            if len(switch_chassis) == 2:
                return DeploymentMode.C9800_HA
            elif len(switch_chassis) == 1:
                return DeploymentMode.C9800_STANDALONE
            return DeploymentMode.UNKNOWN

        """
            Look for VSS information in show inventory

            VSS is identified if show inventory indicates TWO chassis.

            Name of a single chassis inventory item needs to be equal to
            'Chassis {switch num} {pid}', ie 'Chassis 1 C6807-XL'

            On Catalysts 4500 look for two "Switch{slot} System" entries
        """
        vss_chassis_one: bool = False
        vss_chassis_two: bool = False
        for inventory_element in parsed_cisco_ios_show_inventory:
            # Catalyst 6800
            if (
                inventory_element["name"].strip()
                == f"Chassis 1 {inventory_element['pid'].strip()}"
            ):
                vss_chassis_one = True
            # Catalyst 4500X
            elif inventory_element["name"].strip() == "Switch1 System":
                vss_chassis_one = True
            # Catalyst 6800
            elif (
                inventory_element["name"].strip()
                == f"Chassis 2 {inventory_element['pid'].strip()}"
            ):
                vss_chassis_two = True
            # Catalyst 4500X
            elif inventory_element["name"].strip() == "Switch2 System":
                vss_chassis_two = True
        else:
            if vss_chassis_one and vss_chassis_two:
                return DeploymentMode.VSS

        # Return everything else not recognized / excepted as standalone:
        return DeploymentMode.STANDALONE

    def get_multi_device_structured_inventory(
        self, deployment_mode: DeploymentMode
    ) -> list:
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
        if deployment_mode in [
            DeploymentMode.UNKNOWN,
            DeploymentMode.STANDALONE,
            DeploymentMode.C9800_STANDALONE,
        ]:
            raise NotImplementedError("Function does not support this deployment mode")

        parsed_cisco_ios_show_inventory: list = self.get_show_inventory_structured()

        structured_data: List[dict] = []

        if deployment_mode in [
            DeploymentMode.C38XX_STACK,
            DeploymentMode.C93XX_STACK,
            DeploymentMode.C95XX_STACK,
            DeploymentMode.C92XX_STACK,
        ]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # Cisco IOS-XE's "show inventory" indicates a switch whenever
                # name equals to a string like "Switch 1", ... , "Switch 8".
                #
                match: Optional[Match[AnyStr]] = re.search(  # type: ignore
                    "^Switch (\d)$", inventory_element["name"]
                )
                if match:
                    structured_data.append(
                        {
                            "position": int(match.group(1)),
                            "model": self.get_standardized_pid(
                                inventory_element["pid"]
                            ),
                            "serial": inventory_element["sn"],
                        }
                    )

            structured_data = sorted(structured_data, key=lambda i: i["position"])

            if not structured_data:
                raise ValueError(
                    "Could not find appropriate C38/C93 elements in inventory"
                )
            elif structured_data[0]["position"] != 1:
                raise ValueError("Slot 1 missing in stack")

            return structured_data

        elif deployment_mode in [
            DeploymentMode.C3750_STACK,
            DeploymentMode.C2960_STACK,
        ]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # Cisco 2960 & 3750's "show inventory" indicates a switch whenever
                # name equals to a string'ed integer, ie "1", "2", "3"
                #
                if inventory_element["name"] in [str(x) for x in range(1, 10)]:
                    structured_data.append(
                        {
                            "position": int(inventory_element["name"]),
                            "model": self.get_standardized_pid(
                                inventory_element["pid"]
                            ),
                            "serial": inventory_element["sn"],
                        }
                    )

            structured_data = sorted(structured_data, key=lambda i: i["position"])

            if not structured_data:
                raise ValueError(
                    "Could not find appropriate C38/C93 elements in inventory"
                )
            elif structured_data[0]["position"] != 1:
                raise ValueError("Slot 1 missing in stack")

            return structured_data

        elif deployment_mode == DeploymentMode.C9800_HA:
            # C9800 WLC HA is detected when `show chassis` shows 2 chassis members.
            # Get the chassis member specifics using `show inventory`
            # and detect the member hardware by checking for "Chassis {switch_member_number}"

            re_c9800_chassis_inventory_description = re.compile(
                r"^.*C9800.*Chassis\s*$"
            )
            re_c9800_chassis_inventory_name = re.compile(r"^Chassis\s+([1-2])\s*$")

            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # Cat9800 WLCs running IOS-XE "show inventory" indicates a member whenever
                # name equals to a string like "Chassis 1","Chassis 2".
                # the primary device will always have the "Chassis 1" inventory element name
                #

                # check if this inventory element is a chassis member
                if re_c9800_chassis_inventory_description.match(
                    inventory_element.get("descr", "")
                ):
                    match = re_c9800_chassis_inventory_name.match(
                        inventory_element.get("name", "")
                    )

                    if not match:
                        # not actually a chassis member, skip.
                        continue

                    structured_data.append(
                        {
                            "position": int(match.group(1)),
                            "model": self.get_standardized_pid(
                                inventory_element["pid"]
                            ),
                            "serial": inventory_element["sn"],
                        }
                    )

            structured_data = sorted(structured_data, key=lambda i: i["position"])
            if len(structured_data) != 2:
                raise ValueError(
                    f"Cannot get info about chassis members in HA pair as at least one of them are missing from device inventory"
                )

            return structured_data

        elif deployment_mode in [DeploymentMode.VSS]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # VSS is identified if show inventory indicates TWO chassis.
                #
                # Name of a single chassis inventory item needs to be equal to
                # 'Chassis {switch num} {pid}', ie 'Chassis 1 C6807-XL'
                #
                if (
                    inventory_element["name"].strip()
                    == f"Chassis 1 {inventory_element['pid'].strip()}"
                ):
                    structured_data.append(
                        {
                            "position": 1,
                            "model": inventory_element["pid"].strip(),
                            "serial": inventory_element["sn"].strip(),
                        }
                    )
                elif (
                    inventory_element["name"].strip()
                    == f"Chassis 2 {inventory_element['pid'].strip()}"
                ):
                    structured_data.append(
                        {
                            "position": 2,
                            "model": inventory_element["pid"].strip(),
                            "serial": inventory_element["sn"].strip(),
                        }
                    )
                #
                # Name of a single chassis inventory item needs to be equal to
                # 'Switch{num} System'
                #
                # Description is expected to be "Cisco Systems, Inc. WS-C4500X-32 2 slot switch "
                # Model is in the number 4th position
                #
                elif inventory_element["name"].strip() == "Switch1 System":
                    structured_data.append(
                        {
                            "position": 1,
                            "model": inventory_element["descr"].strip().split()[3],
                            "serial": inventory_element["sn"].strip(),
                        }
                    )
                elif inventory_element["name"].strip() == "Switch2 System":
                    structured_data.append(
                        {
                            "position": 2,
                            "model": inventory_element["descr"].strip().split()[3],
                            "serial": inventory_element["sn"].strip(),
                        }
                    )

            structured_data = sorted(structured_data, key=lambda i: i["position"])

            if not structured_data:
                raise ValueError("Could not find appropriate VSS elements in inventory")
            elif len(structured_data) != 2:
                raise ValueError("Invalid length of VSS structured data")
            elif structured_data[0]["position"] != 1:
                raise ValueError("Slot 1 missing in VSS")

            return structured_data

        raise NotImplementedError("Parsing not supported")
