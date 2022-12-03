Value NAME (\d+)
Value MTU (\d+)
Value MAC (([a-f0-9]+-){5}[a-f0-9]+)

Start
  ^${NAME}\s+\w+:\s+\d+\s+\w+:\s+\d+\s+\w+:\s+\d+\s+\w+\s+-\s+\w+\s+\w+\s+\w+\s+${MTU}\s+\d+\s+${MAC} -> Record