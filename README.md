# Rubrik_py

Repository for Python programs which interact with the Rubrik CDM APIs. For more
information on the API, please see:

- https://[cluster IP or FQDN]/docs/v1/playground/
- https://[cluster IP or FQDN]/docs/internal/playground/

# Programs

  brik_info.py

  - Print basic info about the Rubrik Cluster. Need to provide login credentials and URL of the Cluster.

  list_snaps.py

  - When passed a full or partial VM name, prints out a list of matching VMs. If only one match, also
    displays list of snapshots including date, ID and Number of Cloud Archive Snapshots

# Requirements

Python3 including requests

> $ brew install python3
> $ pip install requests

# Tested with

- MacOS 10.13.4 and Python 3.6.4
