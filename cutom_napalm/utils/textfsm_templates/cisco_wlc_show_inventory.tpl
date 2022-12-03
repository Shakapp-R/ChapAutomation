Value BIA_MAC ([\da-zA-Z:]{17})
Value MAX_AP_NUM (\d+)
Value NAME (.*)
Value DESCRIPTION (.*)
Value PID ([\w\-]+)
Value VID (\w+)
Value SN (\w+)

Start
  ^Burned-in\s+MAC\s+Address\.+\s+${BIA_MAC}
  ^Maximum\s+number\s+of\s+APs\s+supported\.+\s+${MAX_AP_NUM}
  ^NAME:\s+"${NAME}"\s+,\s*DESCR:\s+"${DESCRIPTION}"
  ^PID:\s+${PID},\s*VID:\s+${VID},\s*SN:\s+${SN} -> Record
  ^\s*$$
  ^Power\s+Supply\s+\d+.*$$
  ^. -> Error