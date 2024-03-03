import sys
from kev_check import cveState
from cvss4py import score_vector, vector_to_equivalence_class

vulnCVE = sys.argv[1]
vectorString = sys.argv[2]

# main function loop for cvss vector evaluation

print("Welcome to mycvss. This script helps in transforming vendor-supplied CVSSv4.0 assessments"
+ " into adjusted assessments for your environment.")

print("Your CVE to be checked is " + vulnCVE + ". ")

# get CVSS base score

myScore = score_vector(vectorString, validate_vector=True, warn_modified=True, replace_default=True)

print("The base CVSS v4.0 score is ", myScore)

print("First we'll check if your vector string appears in the CISA Known Exploited Vulnerability (KEV) list.")



# call kev_check

foundCVE = cveState(vulnCVE)

# eval based on kev_check, modifying score

if foundCVE:
    print("CVE was found in KEV. Adjusting CVSS.")
    # modify vector, call CVSS check with re-written vector
    vectorString += '/E:A'
else:
    print("CVE was not found in KEV. Adjusting CVSS.")
    vectorString += '/E:U'

# get new base score
myScore = score_vector(vectorString, validate_vector=True, warn_modified=True, replace_default=True)

print("The modified CVSS v4.0 score is ", myScore)
print("The modified vector string is " + vectorString)


