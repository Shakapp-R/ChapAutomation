Value Filldown AP (\S+)
Value Required Int_name (\S+)
Value Status (\S+)
Value Speed (\S+)
Value Rx_packets (\d+)
Value Tx_packets (\d+)
Value Discards (\d+)

Start
  ^\s*AP\s+Interface Name\s+Status\s+Speed\s+Rx Packets\s+Tx Packets\s+Discards -> Row_Detail
  ^\s*$$
  ^.*$$ -> Error

Row_Detail
  ^-+\s
  ^\s*${AP}\s+${Int_name}\s+${Status}\s+${Speed}\s+${Rx_packets}\s+${Tx_packets}\s+${Discards} -> Record
  ^\s*${Int_name}\s+${Status}\s+${Speed}\s+${Rx_packets}\s+${Tx_packets}\s+${Discards} -> Record
  ^\s*$$
  ^.*$$ -> Error