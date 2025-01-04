import json
import os
from pathlib import Path
import objectpath
import re
import numpy as np
from cvss import CVSS3, CVSS4
from scipy import stats as st
import matplotlib.pyplot as plt

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
  allDiffs = np.diff(arr, axis=1)

  # Calculate the average difference
  avg_diff = np.mean(allDiffs)

  return avg_diff

def mode_difference(arr):
    """
    Finds the most common difference between elements of a 2D array.

    Args:
     arr: A 2D NumPy array, the set of CVSS v3.1 and v4.0 scores.

    Returns:
     The most common (ie, the mode) of the score differences
    """
    allDiffs = np.diff(arr, axis=1)
    
    vals,counts = np.unique(allDiffs, return_counts=True)

    index = np.argmax(counts)
    
    return vals[index]

def create_histogram(arr):
    """
    Create a histogram of differences from the supplied array and return it as an object.

    Args:
     arr: A 2D NumPy array, the set of CVSS v3.1 and v4.0 scores.
    
    Returns:
     A matplotlib object of the array of differences.

    """
    allDiffs = np.diff(arr, axis=1)
    
    plt.hist(allDiffs, bins=40, )

    plt.xlabel('Score Change')
    plt.ylabel('Count')
    plt.title('Histogram of CVSS Score Changes')

    plt.show()

    return

