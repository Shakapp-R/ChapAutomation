This repository contains all CHAP internal modifications of NAPALM.

Installation:
### pip

```angular2
pip install git+https://github.com/Shakapp-R/ChapAutomation.git
```

### poetry

```bash
poetry add git+https://github.com/Shakapp-R/ChapAutomation.git
```

Usage:
```angular2
from napalm import get_network_driver
driver_asa = get_network_driver("chap_asa_ssh")
driver_nexus = get_network_driver("chap_nxos_ssh")
```
