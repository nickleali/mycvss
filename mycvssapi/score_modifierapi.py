# the API to return a modified vector string (and score?) based on criteria

import requests

# set up API router

from fastapi import APIRouter

router = APIRouter()

from cvss4py import score_vector, vector_to_equivalence_class

@router.get("/")
def scoreMod(vectorString: str, cve: str):

    # do kev check, modify string accordingly

    kev_check_url = "http://127.0.0.1:8000/kev_checkapi/?search_cve=" + cve

    response = requests.get(kev_check_url)

    cveResponse = response.content
    cveResponse = cveResponse.decode("utf-8")

    kevState = True if cveResponse == 'true' else False

    #modify vector string accordingly based on kevState
    vectorString += '/E:A' if kevState == True else '/E:U'

    # check score for AV:N and if found rewrite string to modify environmental metrics

    if vectorString.find('AV:N') == -1:
        vectorString = vectorString
    else:
        vectorString += '/MAV:A'

    #update our final vector string check
    score_check_url = "http://127.0.0.1:8000/score_checkapi/?vector=" + vectorString

    vectorResponse = requests.get(score_check_url)

    modifiedScore = vectorResponse.content
    modifiedScore = modifiedScore.decode("utf-8")

    return modifiedScore
