Value AP_NAME (\S+)
Value SLOT (\d+)
Value AP_MODEL (\S+)
Value MAC ([a-fA-F0-9:\.]+)
Value LOCATION (.+?)
Value COUNTRY (\S+)
Value IP ([a-fA-F0-9:\.]+)
Value CLIENTS (\d+)
Value PORT (\S+)
Value PRIORITY (\d)


Start
  ^${AP_NAME}\s+${SLOT}\s+${AP_MODEL}\s+${MAC}\s+${LOCATION}\s+${COUNTRY}\s+${IP}\s+${CLIENTS}\s*.*$$ -> Record
  ^${AP_NAME}\s+${SLOT}\s+${AP_MODEL}\s+${MAC}\s+${LOCATION}\s+${PORT}\s+${COUNTRY}\s+${PRIORITY}\s*.*$$ -> Record
  ^.+\.+
  ^\s*$$
  ^AP\s+Name\s+Slots\s+AP\s+Model\s+Ethernet\s+MAC\s+Location\s+Country\s+IP\s+Address\s+Clients\s*.*$$
  ^AP\s+Name\s+Slots\s+AP\s+Model\s+Ethernet\s+MAC\s+Location\s+Port\s+Country\s+Priority\s*.*$$
  ^-+
  ^. -> Error
