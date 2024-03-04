# simple script to check if a CVE exists in the CISA KEV

# set up API router

from fastapi import APIRouter

router = APIRouter()

import json
import urllib.request

@router.get("/",tags=["kev_check"])
async def read_cve(search_cve: str):

    # store the KEV in a local variable

    link = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    with urllib.request.urlopen(link) as url:
        data = json.load(url)

    # store in a string and check that way because I'm bad

    cve_string = json.dumps(data)

    # check logic

    cveFind = cve_string.find(search_cve)

    if cveFind == -1:
        print("The CVE is not in KEV.")
        cveFind = False
    else:
        print("The CVE is in KEV near", cveFind)
        cveFind = True

    return cveFind
