## Zeek Plugin BACnet

When running as part of your Zeek installation this plugin will produce three log files containing metadata extracted from any Ethernet/IP (ENIP) and Common Industrial Protocol (CIP) traffic observed on UDP port 2222 and port 44818 TCP/UDP. Ethernet/IP and CIP are often observed together. `cip.log` and `enip.log` contain metadata from their respective protocols while `enip_list_identity.log` contains addtional data extracted from specific ENIP messages relating to device identity.

## Installation and Usage

`zeek-plugin-enip` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](LICENSE). [Guidelines for contributing](CONTRIBUTING.md) are available as well as a [pull request template](.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin.
