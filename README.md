## Zeek Plugin ENIP

When running as part of your Zeek installation this plugin will produce three log files containing metadata extracted from any Ethernet/IP (ENIP) and Common Industrial Protocol (CIP) traffic observed on UDP port 2222 and port 44818 TCP/UDP. Ethernet/IP and CIP are often observed together. `cip.log` and `enip.log` contain metadata from their respective protocols while `enip_list_identity.log` contains addtional data extracted from specific ENIP messages relating to device identity.

## Installation and Usage

`zeek-plugin-enip` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](https://github.com/amzn/zeek-plugin-enip/blob/master/LICENSE). [Guidelines for contributing](https://github.com/amzn/zeek-plugin-enip/blob/master/CONTRIBUTING.md) are available as well as a [pull request template](https://github.com/amzn/zeek-plugin-enip/blob/master/.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](https://github.com/amzn/zeek-plugin-enip/blob/master/Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin.

## Acknowledgements

* [Earlier work](https://github.com/scy-phy/bro-cip-enip) on CIP and ENIP by [SCy-Phy](http://scy-phy.github.io/)

## Related Work

* [ICSNPP-ENIP](https://github.com/cisagov/icsnpp-enip) - Another ENIP/CIP plugin implementation for Zeek

