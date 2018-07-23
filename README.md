
# Linux Security Baseline 1.0.0-beta

Linux security baseline fix based on CIS Benchmarks.

## Getting Started

Just download the script and run as root.

### Prerequisites

To use this script and apply these security fix, you must run as root:

```
 ./linux-security-baseline.sh -h
 ./linux-security-baseline.sh -b /tmp/backup --root-mailto notify@your-email-domain.br
```

For a complete list of what itens is changed in your Linux system by the script, consult 
CIS Benchmarks documents at: https://www.cisecurity.org/

This current version is based on this controls:
   + CIS Distribution Independent Linux - v1.1.0 12-26-2017  

Tested on:
   + Red Hat Enterprise Linux Server release 7.5 (Maipo) - 3.10.0-862.el7.x86_64

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/daniel-armbrust/linux-security-baseline/tags).

## Authors
* Daniel Armbrust <darmbrust@gmail.com>

## License
GNU General Public License v3.0
