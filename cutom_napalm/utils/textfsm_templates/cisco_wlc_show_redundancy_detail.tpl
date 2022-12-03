Value REDUNDANCY_MGMT_IP ((\d{1,3}\.){3}\d{1,3})
Value PEER_REDUNDANCY_MGMT_IP ((\d{1,3}\.){3}\d{1,3})
Value REDUNDANCY_PORT_IP ((\d{1,3}\.){3}\d{1,3})
Value PEER_REDUNDANCY_PORT_IP ((\d{1,3}\.){3}\d{1,3})
Value PEER_SERVICE_PORT_IP ((\d{1,3}\.){3}\d{1,3})

Start
  ^Redundancy\s+Management\s+IP\s+Address\.+\s+${REDUNDANCY_MGMT_IP}
  ^Peer\s+Redundancy\s+Management\s+IP\s+Address\.+\s+${PEER_REDUNDANCY_MGMT_IP}
  ^Redundancy\s+Port\s+IP\s+Address\.+\s+${REDUNDANCY_PORT_IP}
  ^Peer\s+Redundancy\s+Port\s+IP\s+Address\.+\s+${PEER_REDUNDANCY_PORT_IP}
  ^Peer\s+Service\s+Port\s+IP\s+Address\.+\s+${PEER_SERVICE_PORT_IP} -> Record