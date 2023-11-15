# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [2.0.8] - 2023/11/15
- [DCAEGEN2-3409] Correctly use version 2.2.1 of onap_dcae_cbs_docker_client by specifying it in requirements.txt
- [DCAEGEN2-3409] Explicitly set version for pyasn1 to 0.4.8 to avoid using later versions that are incompatible with pysnmp.
- [DCAEGEN2-3409] Set base image to pypy:3.8 to avoid pulling a later version of python with incompatibilities.

## [2.0.7] - 2022/08/17
- [DCAEGEN2-3158] CodeCoverage improvement for dcaegen2-collectors-snmptrap (60% to 90%)

## [2.0.6] - 2021/10/26
### Changed
* [DCAEGEN2-2957] SNMP Trap collector - STDOUT complaince
* [DCAEGEN2-2995] run the black formatting tool on python code

## [2.0.5] - 2021/07/19
* Changed to use version 2.2.1 of pypi onap_dcae_cbs_docker_client

## [2.0.4] - 2021/02/12
pysnmp version upgraded to 4.4.12 for python >3.7 compatibility

## [2.0.3] - 2020/12/15
