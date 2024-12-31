# script to scan contents of files in a directory for CVSS scores and compare them

# store those and check against them


import json
import os
from pathlib import Path
import objectpath
import re
import numpy as np
from cvss import CVSS3, CVSS4

"""
Set the modes for output:

Set outputCSV to true for CSV output.
Set ouputAllData to true to get all the output of found vectors and scores.

"""

"""
Definitions for various files we're working with.

data_result stores everything we got: v4.0 and v3.1 vectors, their derived scores, and the CVE 

data_csv is a CSV format output of everything
"""

alldata_file = "data_result"

csv_file = "data_csv"
outputCSV = True

data_result = open(alldata_file, 'w')
csv_result = open(csv_file, 'w')

csv_result.write("CVE Name" + ", " + "CVSS v4.0 Vector String" + ", " + "CVSS v4.0 Score" + ", " + "CVSS v3 Vector String" + ", " + "CVSS v3.1 Score")

# Set the list of all the files to check here
result = list(Path("/home/kali/cvelistV5/cves/2024/1xxx").rglob("*.json"))

# Creating our numpy array for the derived scores
# This is a 2D array, first column v3.1, second column v4.0

scoresArray = np.array([[0, 0], [1, 1]])

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

def average_difference(arr):
  """
  Calculates the average between elements of a 2D array.

  Args:
    arr: A 2D NumPy array.

  Returns:
    The average between elements.
  """

  # Calculate the difference between elements and store in a new array
  allDiffs = np.diff(arr)

  # Calculate the average difference
  avg_diff = np.mean(allDiffs)

  return avg_diff

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
                    #print("This is the input to check:" + inputCheck)
                    v4Vector = get_vector(inputCheck, "4.0")
                    #print("This is the returned v4.0 vector" + v4Vector)
                    
                    vendorName = get_cna(fname)
                    print("This is the assigner's name: " + vendorName)

                    # write vector to file
                    # vectors_write.write(v4Vector)

                    # store whole line in local array
                    vector_lines.append(lines[i].strip("\n"))

                    myv4Score = CVSS4(v4Vector)
                    cvssv4Score = str(myv4Score.base_score)

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
                            myv3Score = CVSS3(v3Vector)
                            cvssv3Score = str(myv3Score.base_score)

                            # Just in case store this in the array
                            vector_lines.append(lines[i].strip("\n"))

                            # Write all the v3.1 stuff out.
                            data_result.write("CVSS v3.1 vector: " + v3Vector + "\n" + "CVSS v3.1 score: " + cvssv3Score + "\n")
                            # Write all the stuff out, this is only CVEs with both v3.1 and v4.0 scores

                            if outputCSV:
                                csv_result.write(cveName + ", " + v4Vector + ", " + cvssv4Score + ", " + v3Vector + ", " + cvssv3Score + "\n")

                            # Append to the numpy array
                            newScores = np.array([[float(cvssv3Score), float(cvssv4Score)]])
                            scoresArray = np.append(scoresArray, newScores, axis=0)
            except:
                pass
            
        f.close()
        # print(vector_lines)

        # print the output of the array just to check what we got

        print("This is the output of the array:" + str(scoresArray))


"""
Statistical analysis of the found data

Averages
- average change
- distance of changes
- most common change (mode)

Vulnerability classes
- via regex, search strings for patterns
-- Check on attack vector
-- check on confidentiality / integrity / availability impacts
-- command execution / RCE / ACE (as in, any CIA:High impacts)
- do comparison by classes between v3.1 and v4.0

Graph output
- Histogram of count of changed scores (ie, how many .1 changes, how many .2 changes, etc.)

How do we store the data?

structured array of tuples, matching v3.1 and v4.0 scores
- check how numpy can handle comparisons

Numpy ndarray

"""

# Let's try some stats

# Get the mean of the array

print("This is the average between v3.1 and v4.0 scores for the calculated ranges:")
print(str(average_difference(scoresArray)))
