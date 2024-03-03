
# basic function to return a numeric score based on a CVSS metric string

from cvss4py import score_vector, vector_to_equivalence_class
from kev_check import

myVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A"

myScore = score_vector(myVector, validate_vector=True, warn_modified=True, replace_default=True)

# call kev_check.py

