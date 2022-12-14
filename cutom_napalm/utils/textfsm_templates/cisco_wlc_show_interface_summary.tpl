Value Filldown INT_COUNT (\d+)
Value Required NAME (\S+)
Value PORT (\S+)
Value VLAN (\S+)
Value IP_ADDR (([\d1-9]+\.?){4})
Value TYPE (\S+)
Value AP_MGR (\S+)
Value GUEST (\S+)

Start
  ^\s+Number\sof\sInterfaces\.*\s${INT_COUNT}s*$$
  ^Interface\s+Name\s+Port\s+Vlan\s+Id\s+IP\s+Address\s+Type\s+Ap\s+Mgr\s+Guest -> Type_One
  ^\s*$$
  ^Number\s+of\s+Interfaces.*
  ^. -> Error

Type_One
  ^-+\s
  ^${NAME}\s\s+${PORT}\s+${VLAN}\s+${IP_ADDR}\s+${TYPE}\s+${AP_MGR}\s+${GUEST} -> Record
  ^\s*$$
  ^. -> Error
