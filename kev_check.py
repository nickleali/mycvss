import json
import urllib.request

# simple script to check if a CVE exists in the CISA KEV

# store the KEV in a local variable

link = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

with urllib.request.urlopen(link) as url:
    data = json.load(url)
    #print(data)

# store in a string and check that way?

cve_string = json.dumps(data)

# print(cve_string)

# get the value to search

def cveState(searchCVE):
    #searchCVE = input("Enter CVE to search:")
    #searchCVE = "CVE-2018-0171"
    print("CVE is: "+ searchCVE)

    # check logic

    cveFind = cve_string.find(searchCVE)

    if cveFind == -1:
        print("The CVE is not in KEV.")
        cveFind = False
    else:
        print("The CVE is in KEV near", cveFind)
        cveFind = True

    return cveFind
