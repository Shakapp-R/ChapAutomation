import re

from napalm.base.helpers import (
    textfsm_extractor,
)
from napalm.ios.ios import IOSDriver

from custom_napalm.helpers import GeneralDeploymentMode


class DeploymentMode(GeneralDeploymentMode):
    """ Driver Specific Deployment Mode Class """
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

    VSS = (200, "VssOnboarding")


class BaxterIOSDriver(IOSDriver):
    """Custom NAPALM Cisco IOS Handler."""
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super(BaxterIOSDriver, self).__init__(hostname, username, password, timeout=timeout, optional_args=optional_args)

    @staticmethod
    def get_standardized_pid(pid):
        """
        Fixes and standardizes inconsistencies that occur in IOS:

        - model might be different depending on IOS software version
        - model might have different naming convention on switches

        """
        if pid.endswith('-S') or pid.endswith('-L'):
            return pid[:-2]

        return pid

    def get_show_version_structured(self):
        command = "show version"
        raw_command_output = self._send_command(command)
        print(raw_command_output)
        parsed_cisco_ios_show_version = textfsm_extractor(
            self, "cisco_ios_show_version", raw_command_output
        )

        return parsed_cisco_ios_show_version

    def get_show_inventory_structured(self):
        command = "show inventory"
        raw_command_output = self._send_command(command)
        parsed_cisco_ios_show_inventory = textfsm_extractor(
            self, "cisco_ios_show_inventory", raw_command_output
        )

        return parsed_cisco_ios_show_inventory

    def get_inventory(self):
        """
        Wrapper to get_show_inventory_structured
        """
        return self.get_show_inventory_structured()

    def get_device_deployment_mode(self):
        """
        takes in : parsed_inventory, parsed show version

        :return: $deployment_mode, ie "standalone", "c38xx Stack", etc
        """
        parsed_cisco_ios_show_inventory = self.get_show_inventory_structured()
        parsed_cisco_ios_show_version = self.get_show_version_structured()

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
            if "c38xx Stack".lower() in inventory_element.get('name', "").lower():
                return DeploymentMode.C38XX_STACK
            # c38xx Stacks on ~2013 IOS software shows "c3xxx"
            elif "c3xxx Stack".lower() in inventory_element.get('name', "").lower() \
                    and inventory_element.get('pid', "").lower().startswith('ws-c3850-'):
                return DeploymentMode.C38XX_STACK
            # c93xx Stacks
            elif "c93xx Stack".lower() in inventory_element.get('name', "").lower():
                return DeploymentMode.C93XX_STACK
            # c95xx Stack
            elif "c95xx Stack".lower() in inventory_element.get('name', "").lower():
                return DeploymentMode.C95XX_STACK

        """
            Look for Stack information in show version
            
            2960 & 3750 Stacks are identified based on the show version information.
            If show version indicates more than a single hardware device,
            and if all of them have $modelname string dep. mode is recognized.
        """
        switch_hardware = parsed_cisco_ios_show_version[0].get('hardware', [])

        if len(switch_hardware) > 1:
            if all('C3750' in x for x in switch_hardware):
                return DeploymentMode.C3750_STACK
            elif all('C2960X' in x for x in switch_hardware):
                return DeploymentMode.C2960_STACK
            else:
                return DeploymentMode.UNKNOWN

        """
            Look for VSS information in show inventory
            
            VSS is identified if show inventory indicates TWO chassis.

            Name of a single chassis inventory item needs to be equal to
            'Chassis {switch num} {pid}', ie 'Chassis 1 C6807-XL'
            
            On Catalysts 4500 look for two "Switch{slot} System" entries
        """
        vss_chassis_one = False
        vss_chassis_two = False
        for inventory_element in parsed_cisco_ios_show_inventory:
            # Catalyst 6800
            if inventory_element['name'].strip() == f"Chassis 1 {inventory_element['pid'].strip()}":
                vss_chassis_one = True
            # Catalyst 4500X
            elif inventory_element['name'].strip() == "Switch1 System":
                vss_chassis_one = True
            # Catalyst 6800
            elif inventory_element['name'].strip() == f"Chassis 2 {inventory_element['pid'].strip()}":
                vss_chassis_two = True
            # Catalyst 4500X
            elif inventory_element['name'].strip() == "Switch2 System":
                vss_chassis_two = True
        else:
            if vss_chassis_one and vss_chassis_two:
                return DeploymentMode.VSS

        # Return everything else not recognized / excepted as standalone:
        return DeploymentMode.STANDALONE

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

        parsed_cisco_ios_show_inventory = self.get_show_inventory_structured()

        structured_data = []

        if deployment_mode in [DeploymentMode.C38XX_STACK,
                               DeploymentMode.C93XX_STACK,
                               DeploymentMode.C95XX_STACK]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # Cisco IOS-XE's "show inventory" indicates a switch whenever
                # name equals to a string like "Switch 1", ... , "Switch 8".
                #
                match = re.search("^Switch (\d)$", inventory_element['name'])
                if match:
                    structured_data.append({
                        'position': int(match.group(1)),
                        'model': self.get_standardized_pid(inventory_element['pid']),
                        'serial': inventory_element['sn'],
                    })

            structured_data = sorted(structured_data, key=lambda i: i['position'])

            if not structured_data:
                raise ValueError("Could not find appropriate C38/C93 elements in inventory")
            elif structured_data[0]['position'] != 1:
                raise ValueError("Slot 1 missing in stack")

            return structured_data

        elif deployment_mode in [DeploymentMode.C3750_STACK,
                                 DeploymentMode.C2960_STACK]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # Cisco 2960 & 3750's "show inventory" indicates a switch whenever
                # name equals to a string'ed integer, ie "1", "2", "3"
                #
                if inventory_element['name'] in [str(x) for x in range(1, 10)]:
                    structured_data.append({
                        'position': int(inventory_element['name']),
                        'model': self.get_standardized_pid(inventory_element['pid']),
                        'serial': inventory_element['sn'],
                    })

            structured_data = sorted(structured_data, key=lambda i: i['position'])

            if not structured_data:
                raise ValueError("Could not find appropriate C38/C93 elements in inventory")
            elif structured_data[0]['position'] != 1:
                raise ValueError("Slot 1 missing in stack")

            return structured_data

        elif deployment_mode in [DeploymentMode.VSS]:
            for inventory_element in parsed_cisco_ios_show_inventory:
                #
                # VSS is identified if show inventory indicates TWO chassis.
                #
                # Name of a single chassis inventory item needs to be equal to
                # 'Chassis {switch num} {pid}', ie 'Chassis 1 C6807-XL'
                #
                if inventory_element['name'].strip() == f"Chassis 1 {inventory_element['pid'].strip()}":
                    structured_data.append({
                        'position': 1,
                        'model': inventory_element['pid'].strip(),
                        'serial': inventory_element['sn'].strip(),
                    })
                elif inventory_element['name'].strip() == f"Chassis 2 {inventory_element['pid'].strip()}":
                    structured_data.append({
                        'position': 2,
                        'model': inventory_element['pid'].strip(),
                        'serial': inventory_element['sn'].strip(),
                    })
                #
                # Name of a single chassis inventory item needs to be equal to
                # 'Switch{num} System'
                #
                # Description is expected to be "Cisco Systems, Inc. WS-C4500X-32 2 slot switch "
                # Model is in the number 4th position
                #
                elif inventory_element['name'].strip() == "Switch1 System":
                    structured_data.append({
                        'position': 1,
                        'model': inventory_element['descr'].strip().split()[3],
                        'serial': inventory_element['sn'].strip(),
                    })
                elif inventory_element['name'].strip() == "Switch2 System":
                    structured_data.append({
                        'position': 2,
                        'model': inventory_element['descr'].strip().split()[3],
                        'serial': inventory_element['sn'].strip(),
                    })

            structured_data = sorted(structured_data, key=lambda i: i['position'])

            if not structured_data:
                raise ValueError("Could not find appropriate VSS elements in inventory")
            elif len(structured_data) != 2:
                raise ValueError("Invalid length of VSS structured data")
            elif structured_data[0]['position'] != 1:
                raise ValueError("Slot 1 missing in VSS")

            return structured_data

        raise NotImplementedError("Parsing not supported")
