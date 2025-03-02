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

def modify_vector(searchCVE, vectorString, version):
  """Checks if a CVE is in the KEV and marks up the CVSS vector string accordingly.

  Args:
    searchCVE: the CVE to check in the data source
    vectorString: The CVSS vector.
    version: The version of CVSS to modify.

  Returns:
    The modified CVSS vector, after modifications.

  Consider enabling switches to allow for AV:N -> AV:A adjustments, as well as CR changes (default High, to Medium, etc.)
  """

  # Gotta ensure the string is only the base score, otherwise this check won't work.
  # Concatenate ?

  "kev_check here"
  with open('/tmp/kev/kev.json') as jsonFile:
    kevData = json.load(jsonFile)

  cve_string = json.dumps(kevData)

  cveFind = cve_string.find(searchCVE)

  if cveFind == -1:
    cveFind = False
  else:
    cveFind = True
  
  if cveFind:
    # modify vector, call CVSS check with re-written vector
    # print("Found a CVE to modify.")
    vectorString += '/E:A'
  else:
    vectorString += '/E:U'

  return vectorString

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
    
    values, bins, bars = plt.hist(allDiffs, bins=10, )

    plt.xlabel('Value of Score Change')
    plt.ylabel('Numer of Score Changes')
    plt.bar_label(bars)
    plt.title('Histogram of CVSS Score Changes')

    plt.show()

    return

def create_stacked_graph(arr1, arr2, title):
    """
    Create a stacked histogram that shows the output of a two arrays.

    Args:
     arr1: A NumPy array, the set of values to graph.
     arr2: A NumPy array, the set of values to graph.
     title: The desired title of the graph.
    
    Returns:
     A matplotlib object of the array of differences. 

    The graph should determine best fit for the qualitative ranges, Low, Medium, High, Critical, based on the percentage count.
    Ideally this shows the qualitative boundaries for any data set.

    Top 10% should be critical
    70%-89% should be high
    40-69% should be Medium
    Remainder should be low

    Figure out how to mark up based on the ranges

    Can we use numpy percentile?

    np.percentile(arr, "90")
    """

    """
    For stacked array
    plt.hist(arr1, bins=10, alpha=0.5, label='CVSS v3.1')
    plt.hist(arr2, bins=10, alpha=0.5, label='CVSS v4.0')
    plt.legend(loc='upper right')
    """
    """For side by side arrays"""

    plt.hist([arr1, arr2], bins=20, label=['CVSS v3.1', 'CVSS v4.0'])
    plt.legend(loc='upper right')

    # Try some annotation

    # plt.annotate('v3.1 Stats', xy=[10,10], xytext=[0, 0], textcoords="offset points", ha = 'center', va = 'bottom')

    # No, actually try .text

    # plt.text('v3.1 Stats', horizontalalignment='left', verticalalignment='top')
    #plt.annotate()
    
    plt.title(title)

    print("Some vital statistics about the v3.1 dataset:")
    print("The 90th percentile (start of Critical for range) is: "+ str(np.percentile(arr1, 90)))
    print("The 70th percentile (start of High for range) is: "+ str(np.percentile(arr1, 70)))
    print("The 40th percentile (start of Medium for range) is: "+ str(np.percentile(arr1, 40)))
    print("The 39th percentile (end of Low for range) is: "+ str(np.percentile(arr1, 39)))

    print("And the same for the v4.0 dataset:")
    print("The 90th percentile (start of Critical for range) is: "+ str(np.percentile(arr2, 90)))
    print("The 70th percentile (start of High for range) is: "+ str(np.percentile(arr2, 70)))
    print("The 40th percentile (start of Medium for range) is: "+ str(np.percentile(arr2, 40)))
    print("The 39th percentile (end of Low for range) is: "+ str(np.percentile(arr2, 39)))

    plt.show()

    return

def create_ranges_graph(arr, title):
    """
    Create a graph that shows the output of a 2D array.

    Args:
     arr: A 2D NumPy array, the set of values to graph.
     title: The desired title of the graph.
     twodee: Is the data multidimensional?
    
    Returns:
     A matplotlib object of the array of differences. 

    The graph should determine best fit for the qualitative ranges, Low, Medium, High, Critical, based on the percentage count.
    Ideally this shows the qualitative boundaries for any data set.

    Top 10% should be critical
    70%-89% should be high
    40-69% should be Medium
    Remainder should be low

    Figure out how to mark up based on the ranges

    Can we use numpy percentile?

    np.percentile(arr, "90")
    """
    values, bins, bars = plt.hist(arr, bins=10, label='testing')

    """
    for i in range(len(patches)):
      if i < np.percentile(arr, 39):
        patches[i].set_facecolor('green')
      elif i < np.percentile(arr, 40):
        patches[i].set_facecolor('yellow')
      elif i < np.percentile(arr, 70):
        patches[i].set_facecolor('orange')
      else:
        patches[i].set_facecolor('red')
    """
    print("Some vital statistics about this dataset:")
    print("The 90th percentile (start of Critical for range) is: "+ str(np.percentile(arr, 90)))
    print("The 70th percentile (start of High for range) is: "+ str(np.percentile(arr, 70)))
    print("The 40th percentile (start of Medium for range) is: "+ str(np.percentile(arr, 40)))
    print("The 39th percentile (end of Low for range) is: "+ str(np.percentile(arr, 39)))

    plt.xlabel('Scores')
    plt.ylabel('Count')
    plt.title(title)

    plt.show()

    return

def determine_ranges(arr):
    """
    Return the range of differences, as in, the difference between the minium value of the array and the maximuim value of the array.

    Args:
     arr: A 2D NumPy array, the set of CVSS v3.1 and v4.0 scores.
    
    Returns:
     One value: by finding the minium and maximum value of the array, this function returns the difference between those values.
    """
    allDiffs = np.diff(arr, axis=1)

    maxDiff = allDiffs.max()

    minDiff = allDiffs.min()
    
    rangeDiff = maxDiff - minDiff

    return rangeDiff