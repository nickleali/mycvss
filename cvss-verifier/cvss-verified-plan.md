# Plan

This is a dashboard that reports differences between vendor-supplied CVSS scores and assessments from other sources.

Be able to search on types of vulnerabilities and classes.

Get everything and store in SQL for CVE and then search based on that. 


Ask CIRCUIT for a database design and implementation based on the data in the page, also python connectors and SQL statements. 





## prepro

Go back through history and grab all the CVMAP data.

Create a python script that will go grab all the pages from CVMAP (eg https://nvd.nist.gov/vuln/cvmap/report/100) and store everything locally to compare later.

Create a python script using selenium that will save each link 

## pivot to full data

Get all the scores out of CVE program and NVD data and just work from there.

https://nvd.nist.gov/vuln/data-feeds#APIS

      "metrics" : {
        "cvssMetricV31" : [ {
          "source" : "psirt@cisco.com",
          "type" : "Secondary",
          "cvssData" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",

https://github.com/CVEProject/cvelistV5/tree/main/cves

CVE-2024-20251

## init

## Description: compare the sets of reports from NVD to systematically determine the gaps in CVE descriptions

grab everything from each CVMAP report and stuff it into SQL for later comparison

### script prompt 1

Create a python script that will look at this web page (https://nvd.nist.gov/vuln/cvmap/report/21190) and determine the vendor name. The vendor name appears in the page body, after the words "CVSS v3.1 Statistics for" and prior to the date.

Check each report, identified by the number at the end of this URL https://nvd.nist.gov/vuln/cvmap/report/21190 beginning with 1 and ending with 22000, for this vendor name.

Store the name of each vendor and the listed report ID name in a file.

### script prompt 2

Look at the site in the example URL here: https://nvd.nist.gov/vuln/cvmap/report/21190

Create a python script that will take all the text 

Note the table column values are labeled for the CNA and the NIST program. 

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

All the comparisons. How can we best figure out the differences?

### Database design

How can we set this up?

### Slice and search by vendor

Be able to search on a per-vendor basis. Grab all the data out of the JSON and search.

### Data examination between sets

determine the differences between the NVD and PSIRT CVSS vector strings in the provided CSV for each CVE and summarize the top three most common differences between the sets of CVSS vectors