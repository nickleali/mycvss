# script to scan contents of files in a directory for CVSS scores and compare them

# store those and check against them


import json
import os
from pathlib import Path
import objectpath
import re
from cvss import CVSS3, CVSS4

"""
Definitions for various files we're working with.

data_result stores everything we got: v4.0 and v3.1 vectors, their derived scores, and the CVE 
"""

alldata_file = "data_result"

data_result = open(alldata_file, 'w')

# Set the list of all the files to check here
result = list(Path("/home/kali/cvelistV5/cves/2024").rglob("*.json"))

def get_vector(vector, version):
  """Searches a string for a CVSS vector and returns the vector string only.

  Args:
    vector: The dirty vector text.
    version: The version of CVSS vector to search for.

  Returns:
    The CVSS vector, or None if the pattern is not found.
  """

  match = re.search(vector, version)
  match = str(match)
  print("This is the match:" + match)
  if version == "3.1":
      print("Checking for v3.1 score.")
      if match:
          start_index = 17
          end_index = start_index + 44
          return vector[start_index:end_index]
      else:
          return None
  elif version == "4.0":
      if match:
          print("Checking for v4.0 score.")
          start_index = 17
          end_index = start_index + 63
          return vector[start_index:end_index]
      else:
          return None
  else:
      return "Invalid CVSS vector version"

# return v4.0 and then corresponding v3.1 from a file, store in an array
# JSON format sorts in descending order, so v4.0 is always first

for fname in result:
    if os.path.isfile(fname):
        # Full path
        f = open(fname)
        lines = f.readlines()

        vector_lines = []
        for i in range(len(lines)):
            # print(lines)
            try:
                if "CVSS:4.0" in lines[i]:
                    print('Found CVSS vectors in file %s' % fname)
                    # Get clean v4 vector
                    inputCheck = str(lines[i])
                    inputCheck = inputCheck.strip()
                    print("This is the input to check:" + inputCheck)
                    v4Vector = get_vector(inputCheck, "4.0")
                    print("This is the returned v4.0 vector" + v4Vector)

                    # write vector to file
                    # vectors_write.write(v4Vector)

                    # store whole line in local array
                    vector_lines.append(lines[i].strip("\n"))

                    myScore = CVSS4(v4Vector)
                    myScore = str(myScore.base_score)

                    # Write all the v4.0 stuff out.
                    cveName = str(fname)
                    data_result.write(cveName + "\n" + myScore + "\n")

                    #print(vector_lines)
                    for i in range(len(lines)):
                        if "CVSS:3.1" in lines[i]:
                            # call to get a clean vector
                            inputCheck = str(lines[i])
                            inputCheck = inputCheck.strip()
                            print("This is the input to check:" + inputCheck)
                            v3Vector = get_vector(inputCheck, "3.1")
                            print("This is the returned v3.1 vector" + v4Vector)
                       
                            # get the score of this vector
                            myScore = CVSS3(v3Vector)
                            myScore = str(myScore.base_score)

                            # Just in case store this in the array
                            vector_lines.append(lines[i].strip("\n"))

                            # Write all the v3.1 stuff out.
                            data_result.write(myScore + "\n")
            except:
                pass
            
        f.close()
        # print(vector_lines)
