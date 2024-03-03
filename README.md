# mycvss

A starting place for the CVSS transformer tool, mycvss.

To run, you will need to install the cvss4py library from:
pip install git+https://github.com/bjedwards/cvss4py

Usage:

Run mycvss passing desired CVE and base CVSS metric string.

Example:

python3 mycvss.py CVE-2024-20244 CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L
