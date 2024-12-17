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

data_csv is a CSV format output of everything
"""

alldata_file = "data_result"

csv_file = "data_csv"

data_result = open(alldata_file, 'w')
csv_result = open(csv_file, 'w')

csv_result.write("CVE Name" + ", " + "CVSS v4.0 Vector String" + ", " + "CVSS v4.0 Score" + ", " + "CVSS v3 Vector String" + ", " + "CVSS v3.1 Score")

# Set the list of all the files to check here
result = list(Path("/home/kali/cvelistV5/cves").rglob("*.json"))

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
  if version == "3.1":
      # print("Checking for v3.1 score.")
      if match:
          start_index = vector.index("CVSS:3.1")
          end_index = start_index + 44
          return vector[start_index:end_index]
      else:
          return None
  elif version == "4.0":
      if match:
          #print("Checking for v4.0 score.")
          start_index = vector.index("CVSS:4.0")
          end_index = start_index + 63
          return vector[start_index:end_index]
      else:
          return None
  else:
      return "Invalid CVSS vector version"

def get_cna(cve_file):
  """Searches a CVE program json file and returns the value of the assignerShortName field.

  Args:
    cve_file: the file path to search for the pattern.

  Returns:
    The value of the assignerShortName field, or None if the pattern is not found.
  """

  f = open(cve_file)
  lines = f.readlines()

  for i in range(len(lines)):
      inputCheck = str(lines[i])
      inputCheck = inputCheck.strip()
      # print("This is the line to check:" + inputCheck)
      try: 
          match = re.search("assignerShortName", inputCheck)
          match = str(match)
          if match:
              start_index = inputCheck.index("assignerShortName")
              end_index = inputCheck.index("\",")
              assignerName = inputCheck[start_index:end_index]
              # print("We found the assigner's name:" + assignerName + "***********")
              return assignerName
          else:
              return False 
              # print("name not found")
      except:
          pass

# return v4.0 and then corresponding v3.1 from a file, store in an array
# JSON format sorts in descending order, so v4.0 is always first

#write CSV file headers

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
                    #print("This is the input to check:" + inputCheck)
                    v4Vector = get_vector(inputCheck, "4.0")
                    #print("This is the returned v4.0 vector" + v4Vector)
                    
                    vendorName = get_cna(fname)
                    print("This is the assigner's name: " + vendorName)

                    # write vector to file
                    # vectors_write.write(v4Vector)

                    # store whole line in local array
                    vector_lines.append(lines[i].strip("\n"))

                    myScore = CVSS4(v4Vector)
                    cvssv4Score = str(myScore.base_score)

                    # Write all the v4.0 stuff out.
                    cveName = str(fname)
                    cve_start_index = cveName.index("CVE-")
                    cve_end_index = cveName.index(".")
                    cveName = cveName[cve_start_index:cve_end_index]
                    data_result.write(cveName + "\n" + vendorName + "\n" + "CVSS v4.0 vector: " + v4Vector + "\n" + "CVSS v4.0 score: " + cvssv4Score + "\n")
                    # csv_result.write(cveName + ", " + v4Vector + ", " + cvssv4Score + ", " + "\n")

                    #print(vector_lines)
                    for i in range(len(lines)):
                        if "CVSS:3.1" in lines[i]:
                            # call to get a clean vector
                            inputCheck = str(lines[i])
                            inputCheck = inputCheck.strip()
                            #print("This is the input to check:" + inputCheck)
                            v3Vector = get_vector(inputCheck, "3.1")
                            #print("This is the returned v3.1 vector" + v4Vector)
                       
                            # get the score of this vector
                            myScore = CVSS3(v3Vector)
                            cvssv3Score = str(myScore.base_score)

                            # Just in case store this in the array
                            vector_lines.append(lines[i].strip("\n"))

                            # Write all the v3.1 stuff out.
                            data_result.write("CVSS v3.1 vector: " + v3Vector + "\n" + "CVSS v3.1 score: " + cvssv3Score + "\n")
                            # Write all the stuff out, this is only CVEs with both v3.1 and v4.0 scores
                            csv_result.write(cveName + ", " + v4Vector + ", " + cvssv4Score + ", " + v3Vector + ", " + cvssv3Score + "\n")
            except:
                pass
            
        f.close()
        # print(vector_lines)
