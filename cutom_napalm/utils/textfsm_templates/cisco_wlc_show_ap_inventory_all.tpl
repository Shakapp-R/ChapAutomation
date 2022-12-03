Value HOSTNAME (.+)
Value NAME (.+)
Value DESCR (.+)
Value PID (([\S+]+|.*))
Value VID (.*)
Value SN ([\w+\d+]+)

Start
  ^Inventory for ${HOSTNAME}
  ^\s*NAME:\s+"${NAME}"\s*,\s+DESCR:\s+"${DESCR}"
  ^PID:\s+${PID}.*,.*VID:\s+${VID},.*SN:\s+${SN} -> Record
  ^PID:\s+,.*VID:\s+${VID},.*SN: -> Record
  ^PID:\s+${PID}.*,.*VID:\s+${VID},.*SN: -> Record
  ^PID:\s+,.*VID:\s+${VID},.*SN:\s+${SN} -> Record
  ^PID:\s+${PID}.*,.*VID:\s+${VID}.*
  ^PID:\s+,.*VID:\s+${VID}.*
  ^.*SN:\s+${SN} -> Record
  ^.*SN: -> Record
