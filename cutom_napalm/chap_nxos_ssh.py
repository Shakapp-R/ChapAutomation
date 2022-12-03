import re

from napalm.base.helpers import textfsm_extractor

from napalm.nxos_ssh.nxos_ssh import NXOSSSHDriver

from custom_napalm.helpers import GeneralDeploymentMode


class DeploymentMode(GeneralDeploymentMode):
    """ Driver Specific Deployment Mode Class """
    UNKNOWN = (0, None)
    STANDALONE = (1, "StandaloneOnboarding")
    FEX = (301, "NxosFexOnboarding")


class BaxterNXOSSSHDriver(NXOSSSHDriver):
    """Custom NAPALM Cisco NXOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super(BaxterNXOSSSHDriver, self).__init__(hostname, username, password, timeout=timeout,
                                                  optional_args=optional_args)

    def get_facts(self):
        facts = super(BaxterNXOSSSHDriver, self).get_facts()

        try:
            show_inventory_table = self._get_command_table(
                "show inventory | json", "TABLE_inv", "ROW_inv"
            )
            if isinstance(show_inventory_table, dict):
                show_inventory_table = [show_inventory_table]

            for row in show_inventory_table:
                if row["name"] == '"Chassis"' or row["name"] == "Chassis":
                    model = row.get("productid", "")
                    break
        except ValueError:
            show_inventory = self._send_command("show inventory")
            find_regexp = r"^NAME:\s+\"(.*)\",.*\n^PID:\s+(\S+).*SN:\s+(\w*)"
            find = re.findall(find_regexp, show_inventory, re.MULTILINE)
            for row in find:
                if row[0] == "Chassis":
                    model = row[1]
                    break

        facts['model'] = model

        return facts

    def get_show_fex_structured(self):
        command = "show fex"
        raw_command_output = self._send_command(command)
        parsed_cisco_nxos_show_fex = textfsm_extractor(
            self, "cisco_nxos_show_fex", raw_command_output
        )
        return parsed_cisco_nxos_show_fex
    
    def get_device_deployment_mode(self):
        parsed_show_fex = self.get_show_fex_structured()

        if parsed_show_fex==[]:
            return DeploymentMode.STANDALONE
        else:
            return DeploymentMode.FEX
    
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
        if not deployment_mode == DeploymentMode.FEX:
            raise NotImplementedError("Function does not support this deployment mode")

        parsed_show_fex = self.get_show_fex_structured()

        if len(parsed_show_fex) == 0:
            raise ValueError(f"Device is in mode {deployment_mode} but has no fex connected to it")

        fex_list = []
        for fex in parsed_show_fex:
            fex_dict = {
                'position': fex['number'],
                'model': fex['model'],
                'serial': fex['serial'],
            }
            fex_list.append(fex_dict)

        return fex_list
