Value NAME ([a-zA-Z-]+)
Value MAC (([a-f0-9]{2}:){5}[a-f0-9]{2})
Value IP ((\d{1,3}\.){3}\d{1,3})
Value MASK ((\d{1,3}\.){3}\d{1,3})

Start
  ^Interface\s+Name\.+\s+${NAME}
  ^MAC\s+Address\.+\s+${MAC}
  ^IP\s+Address\.+\s+${IP}
  ^IP\s+Netmask\.+\s+${MASK}
