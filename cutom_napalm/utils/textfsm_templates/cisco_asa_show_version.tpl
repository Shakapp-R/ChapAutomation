Value VERSION (\S+)
Value DEVICE_MGR_VERSION (\S+)
Value COMPILE_DATE (\d+-\w+-\d+)
Value IMAGE (\S+)
Value HOSTNAME (\S+)
Value UPTIME (.+)
Value HARDWARE (.+?)
Value MODEL (\S+)
Value FLASH (\S+)
Value List INTERFACES (\S+)
Value LICENSE_MODE (.+)
Value LICENSE_STATE (.+)
Value MAX_INTF (\S+)
Value MAX_VLANS (\d+)
Value FAILOVER (\S+)
Value CLUSTER (\S+)
Value List SERIAL (\S+)
Value LAST_MOD (.+)

Start
  ^.*Software\sVersion\s${VERSION}
  ^Device.+\s${DEVICE_MGR_VERSION}
  ^Compiled\s+on\s+\w+\s+${COMPILE_DATE}.*
  ^System image file.+"${IMAGE}"
  ^${HOSTNAME} up ${UPTIME}
  ^Hardware:\s+${HARDWARE},?\s*$$
  ^Model Id:\s+${MODEL}
  ^Internal.+Flash,\s${FLASH}
  ^\s*\d+:.\S+\s*${INTERFACES}.*
  ^License mode:\s${LICENSE_MODE}
  ^.+License State:\s${LICENSE_STATE}
  ^Maximum Physical.+:\s${MAX_INTF}
  ^Maximum VLANs.+:\s${MAX_VLANS}
  ^Failover\s+:\s${FAILOVER}
  ^Cluster\s+:\s${CLUSTER}
  ^Serial Number:\s${SERIAL}
  ^.+last modified by\s${LAST_MOD}