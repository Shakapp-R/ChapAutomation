Value NAME (\d+)
Value ADMIN_MODE (\w+)
Value SPEED (\d+)
Value STATUS (\w+)

Start
  ^${NAME}\s+\w+\s+\w+\s+${ADMIN_MODE}\s+\w+\s+(${SPEED}\s\w+|\w+\s+)\s+${STATUS}.* -> Record