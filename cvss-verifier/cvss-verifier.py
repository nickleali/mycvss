## init

## Description: compare the sets of reports from NVD to systematically determine the gaps in CVE descriptions

## Get data from NVD

### Get the entire NVD and CVE github, parse through it, and store CVSS in a database

#### https://nvd.nist.gov/vuln/data-feeds

## Get data out of the report as well and put that with the related record, getting the "Reason" for reference

### https://nvd.nist.gov/vuln/cvmap/report/21025


### Comparisons
### Compare the different CVSS values in each CVE

#### Compare string to examples based on CWE
#### If there is a strong mismatch, there may be an error




## Dashboard

### Slice and search by vendor

import cvss_differ

# Example Usage:
v1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
v2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
print(cvss_differ.compare_cvss_vectors(v1, v2))  # Output: None

v3 = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
print(cvss_differ.compare_cvss_vectors(v1, v3))  # Output: {'AV': False, 'AC': True, ...}