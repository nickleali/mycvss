# set up API router

from fastapi import APIRouter

router = APIRouter()

# basic function to return a numeric score based on a CVSS metric string

from cvss4py import score_vector, vector_to_equivalence_class

@router.get("/")
def vectorCheck(vector: str):
    myScore = score_vector(vector, validate_vector=True, warn_modified=True, replace_default=True)
    return myScore
