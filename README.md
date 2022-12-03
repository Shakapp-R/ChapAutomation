This repository contains all Baxter's internal modifications of NAPALM.

The idea is to create a customized NAPALM driver for devices and store Baxter's logic in the new driver.
The drivers inherit from NAPALM, so they don't replace or change any existing NAPALM code but rather extend it with required scope.

Installation:
### pip

```angular2
pip install git+https://gitlab.europe.baxter.com/EMEA-NetworkServices/baxnapalm.git
```

### poetry

```bash
poetry add git+https://gitlab.europe.baxter.com/EMEA-NetworkServices/baxnapalm.git
```

Usage:
```angular2
from napalm import get_network_driver
driver_asa = get_network_driver("baxter_asa_ssh")
driver_nexus = get_network_driver("baxter_nxos_ssh")
```
