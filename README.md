# mycvss

A starting place for the CVSS transformer tool, mycvss.

See documentation on CVSS v4.0 at first.org/cvss

To run, you will need to install the cvss4py library from:
pip install git+https://github.com/bjedwards/cvss4py

Usage:

Run mycvss passing desired CVE and base CVSS metric string.

Example:

python3 mycvss.py CVE-2024-20244 CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L

## APIs

These simple FastAPI-based scripts provide simple CVSS v4.0 checking functionality.

Run FastAPI services from the /mycvssapi folder with the following:

uvicorn main:app --reload

The APIs include:

kev_checkapi to determine the existence of the provided CVE in the CISA KEV.

score_checkapi.py to return a base CVSS score from a provided CVSS v4.0 base metric string.

score_modifier.py to return a modified CVSS B+T+E score based on criteria, including the existence of the CVE in the CISA KEV, compensating controls on network attack vectors, and more to come.

## WebUI

The /mycvssui folder contains a simple web user interface to show the transforms between base and modified base + threat + environmental score.

This front end is based on the APIs above. The APIs must be running to support the web UI.

## Other CVSS Helper Tools

### cvss-enum Tools

This set of tools will output valid CVSS v4 vector strings for use in testing calculator implementations. There are three scripts currently.

The base_enum script will output all valid CVSS v4 Base scores.

The base_threat_enum script will output all valid CVSS v4 Base+Threat scores.

Currently work in process vector_enum script will output all valid 15 million CVE v4 Base+Threat+

### cvss-scraper Tools

A set of tools to directly check CVSS scores against the official CVSS calculator at first.org/cvss since currently there is no API implementation and it can be a challenge to get official scores out of the currently implemented Vue app.


