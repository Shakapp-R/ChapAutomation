Value NUMBER (\d+)
Value DESCR ((\S+)(\s+\S+)*)
Value STATE (\S+)
Value MODEL (\S+)
Value SERIAL (\S+)

Start
  ^${NUMBER}\s+${DESCR}\s+${STATE}\s+${MODEL}\s+${SERIAL} -> Record