Value VERSION (.+?)
Value ROMMON (\S+)
Value HOSTNAME (\S+)
Value UPTIME (.+)
Value RELOAD_REASON (.+?)
Value RUNNING_IMAGE (\S+)
Value List HARDWARE (\S+\d\S+)
Value List SERIAL (\S+)
Value CONFIG_REGISTER (\S+)
Value List MAC ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})

Start
  ^.*Software\s.+\),\sVersion\s${VERSION},*\s+RELEASE.*
  ^ROM: ${ROMMON}
  ^\s*${HOSTNAME}\s+uptime\s+is\s+${UPTIME}
  ^[sS]ystem\s+image\s+file\s+is\s+"(.*?):${RUNNING_IMAGE}"
  ^(?:[lL]ast\s+reload\s+reason:|System\s+returned\s+to\s+ROM\s+by)\s+${RELOAD_REASON}\s*$$
  ^[Pp]rocessor\s+board\s+ID\s+${SERIAL}
  ^[Cc]isco\s+${HARDWARE}.+
  ^[Cc]onfiguration\s+register\s+is\s+${CONFIG_REGISTER}
  ^Base [Ee]thernet MAC [Aa]ddress\s+:\s+${MAC}
  ^Switch Port -> Stack
  # Capture time-stamp if vty line has command time-stamping turned on
  ^Load\s+for\s+
  ^Time\s+source\s+is


Stack
  ^[Ss]ystem [Ss]erial [Nn]umber\s+:\s+${SERIAL}
  ^[Mm]odel\s+[Nn]umber\s+:\s+${HARDWARE}\s*
  ^[Cc]onfiguration\s+register\s+is\s+${CONFIG_REGISTER}
  ^Base [Ee]thernet MAC [Aa]ddress\s+:\s+${MAC}