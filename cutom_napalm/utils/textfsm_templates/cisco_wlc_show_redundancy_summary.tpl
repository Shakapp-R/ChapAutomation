Value NON_HA_PAIR (\w+)
Value REDUNDANCY_MODE (.*)
Value LOCAL_STATE (.*)
Value PEER_STATE (.*)
Value UNIT (.*)
Value UNIT_ID (.*)
Value REDUNDANCY_STATE (.*)
Value MOBILITY_MAC (.*)
Value REDUNDANCY_PORT (.*)
Value PEER_LATENCY (.+)
Value GATEWAY_LATENCY (.+)

Start
  ^\s*Type.+=\s+${NON_HA_PAIR} -> Record
  ^\s+Redundancy\s+Mode\s+=\s+${REDUNDANCY_MODE}
  ^\s+Local\s+State\s+=\s+${LOCAL_STATE}
  ^\s+Peer\s+State\s+=\s+${PEER_STATE}
  ^\s+Unit\s+=\s+${UNIT}
  ^\s+Unit\s+ID\s+=\s+${UNIT_ID}
  ^\s+Redundancy\s+State\s+=\s+${REDUNDANCY_STATE}
  ^\s+Mobility\s+MAC\s+=\s+${MOBILITY_MAC}
  ^\s+Redundancy\s+Port\s+=\s+${REDUNDANCY_PORT}
  ^Average\s+Redundancy\s+Peer\s+Reachability\s+Latency\s+=\s+${PEER_LATENCY}
  ^Average\s+Management\s+Gateway\s+Reachability\s+Latency\s+=\s+${GATEWAY_LATENCY} -> Record
