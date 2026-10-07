# get_esxi_ver

This directory contains a helper program to obtain and print the ESX/ESXi build number (from a guest VM running Linux on x86_64).

# Prerequisites

* Usual build tools (including make)
* musl-gcc

# Building the helper tool

```
make
```

# Arming the script

Place the base64-encoded executable into the 'ESX_HELPER_x86_64' variable of the 'easy_triage.sh' script.
