Value IDENTIFIER (.+?)
Value NAME (.+?)
Value COUNTRY_CODE (\S+)
Value COUNTRY (.+?)
Value MAC (.+?)
Value IP (.+?)
Value NETMASK (.+?)
Value GATEWAY (.+?)
Value AP_GROUP (.+?)
Value PRIMARY_SWITCH_NAME (.+?)
Value PRIMARY_SWITCH_IP (.+?)
Value SECONDARY_SWITCH_NAME (.+?)
Value SECONDARY_SWITCH_IP (.+?)
Value TERTIARY_SWITCH_NAME (.+?)
Value TERTIARY_SWITCH_IP (.+?)
Value ADMINISTRATIVE_STATE (.+?)
Value OPERATION_STATE (.+?)
Value MODE (.+?)
Value MODEL (.+?)
Value IMAGE (.+?)
Value VERSION (.+?)
Value SERIAL_NUMBER (.+?)
Value FLEXCONNECT_VLAN_MODE (.+?)
Value UPTIME (.+?)
Value LWAPP_UPTIME (.+?)
Value JOIN_DATE_TIME (.+?)
Value JOIN_TAKEN_TIME (.+?)

Start
  ^Cisco\s+AP\s+Identifier\.*\s+${IDENTIFIER}\s*$$
  ^Cisco\s+AP\s+Name\.*\s+${NAME}\s*$$
  ^Country\s+code\.*\s+${COUNTRY_CODE}\s+-\s+${COUNTRY}\s*$$
  ^MAC\s+Address\.*\s+${MAC}\s*$$
  ^IP\s+Address\.*\s+${IP}\s*$$
  ^IP\s+NetMask\.*\s+${NETMASK}\s*$$
  ^Gateway\s+IP\s+Addr\.*\s+${GATEWAY}\s*$$
  ^Cisco\s+AP\s+Group\s+Name\.*\s+${AP_GROUP}\s*$$
  ^Primary\s+Cisco\s+Switch\s+Name\.*\s+${PRIMARY_SWITCH_NAME}\s*$$
  ^Primary\s+Cisco\s+Switch\s+IP\s+Address\.*\s+${PRIMARY_SWITCH_IP}\s*$$
  ^Secondary\s+Cisco\s+Switch\s+Name\.*\s+${SECONDARY_SWITCH_NAME}\s*$$
  ^Secondary\s+Cisco\s+Switch\s+IP\s+Address\.*\s+${SECONDARY_SWITCH_IP}\s*$$
  ^Tertiary\s+Cisco\s+Switch\s+Name\.*\s+${TERTIARY_SWITCH_NAME}\s*$$
  ^Tertiary\s+Cisco\s+Switch\s+IP\s+Address\.*\s+${TERTIARY_SWITCH_IP}\s*$$
  ^Administrative\s+State\s+\.*\s+${ADMINISTRATIVE_STATE}\s*$$
  ^Operation\s+State\s+\.*\s+${OPERATION_STATE}\s*$$
  ^AP\s+Mode\s+\.*\s+${MODE}\s*$$
  ^AP\s+Model\.*\s+${MODEL}\s*$$
  ^AP\s+Image\.*\s+${IMAGE}\s*$$
  ^IOS\s+Version\.*\s+${VERSION}\s*$$
  ^AP\s+Serial\s+Number\.*\s+${SERIAL_NUMBER}\s*$$
  ^FlexConnect\s+Vlan\s+mode\s+:\.+\s+${FLEXCONNECT_VLAN_MODE}\s*$$
  ^AP\s+Up\s+Time\.*\s+${UPTIME}\s*$$
  ^AP\s+LWAPP\s+Up\s+Time\.*\s+${LWAPP_UPTIME}\s*$$
  ^Join\s+Date\s+and\s+Time\.*\s+${JOIN_DATE_TIME}\s*$$
  ^Join\s+Taken\s+Time\.*\s+${JOIN_TAKEN_TIME}\s*$$ -> Record
  ^.+\.+
  ^-+
  ^\s*$$
  ^\S+\s+VLAN.+Mappings
  ^\s+Template\s+in\s+
  ^AP-Specific\s+FlexConnect
  ^FlexConnect\s+Local-Split
  ^WLAN\s+ID\s+PROFILE\s+NAME\s+ACL\s+TYPE\s*$$
  ^\s+Flexconnect\s+Central-Dhcp
  ^WLAN\s+ID\s+PROFILE NAME\s+Central-Dhcp\s+DNS\s+Override\s+Nat-Pat\s+Type\s*$$
  ^\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^WlanId\s+PROFILE NAME\s+Inherit-level\s+Visibility\s+Flex\s+Avc-profile\s*$$
  ^\d+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^\d+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^\d+\s+\S+\s+\S+\s+\S+\s+\S+\s*$$
  ^FlexConnect\s+Backup\s+Auth
  ^\s*Time Zone Config\s*:\s*$$
  ^.+\.+.+$$
  ^\s*ApVapId to Profile Name Mappings\s*:\s*$$
  ^\s*APVAPID\s+WLANID\s+PROFILE NAME\s+SLOT-A/B\s*$$
  ^\s*\d+\s+\d+\s+\S+\s+\S+\s*$$
  ^. -> Error