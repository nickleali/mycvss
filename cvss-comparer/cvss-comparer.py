# script to scan contents of files in a directory for CVSS scores and compare them

# store those and check against them


import json
import os
from pathlib import Path
import objectpath
import re
import numpy as np
from cvss import CVSS3, CVSS4
import matplotlib.pyplot as plt

#import our functions in comfunctions.py

from comfunctions import *

"""
Set the modes for output:

Set outputCSV to true for CSV output.
Set ouputAllData to true to get all the output of found vectors and scores.
Set vendorCheck to true to get vendor results

"""

"""
Definitions for various files we're working with.

data_result stores everything we got: v4.0 and v3.1 vectors, their derived scores, and the CVE 

data_csv is a CSV format output of everything
"""

vendorCheck = False

alldata_file = "data_result"
ouputAllData = True

csv_file = "data_csv"
outputCSV = True

data_result = open(alldata_file, 'w')
csv_result = open(csv_file, 'w')

csv_result.write("CVE Name" + ", " + "CVSS v4.0 Vector String" + ", " + "CVSS v4.0 Score" + ", " + "CVSS v3 Vector String" + ", " + "CVSS v3.1 Score")

# Set the list of all the files to check here
result = list(Path("/home/kali/cvelistV5/cves/2024").rglob("*.json"))

# Creating our numpy array for the derived scores
# This is a 2D array, first column v3.1, second column v4.0

scoresArray = np.array([[0, 0], [1, 1]])

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
                    # print('Found CVSS vectors in file %s' % fname)
                    # Get clean v4 vector
                    inputCheck = str(lines[i])
                    inputCheck = inputCheck.strip()
                    #print("This is the input to check:" + inputCheck)
                    v4Vector = get_vector(inputCheck, "4.0")
                    #print("This is the returned v4.0 vector" + v4Vector)
                    
                    vendorName = get_cna(fname)
                    if vendorCheck:
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
                    if ouputAllData:
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
                            if ouputAllData:
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

        # print("This is the output of the array:" + str(scoresArray))

"""
Write code segment to search not a set of files but a file itself for strings and score them

So that it will also work with a single file, csv or whatever

Code switch or something to detect usage


"""

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

Classification of vulnerabilities
- look at counts of CWEs and relate those to the differences in scoring
-- did the type of vulnerabilities each year influence the overall scoring changes?


# Basic stats

# The whole array

print(scoresArray)

# Get the mean of the array

print("This is the average between v3.1 and v4.0 scores for the calculated ranges:")
print(str(average_difference(scoresArray)))

# Get the average change, the mode

print("This is the most common change for the calculated ranges:")
print(str(mode_difference(scoresArray)))

# Get the whole set of changes, as in, each unique difference

print("This is the histogram of the differences")
plt.show(create_histogram(scoresArray))
"""

# attempt at main program loop
# rework using input()

print("Analysis complete. Select the following options for output.")
print("Press the d key for all the raw data found.")
print("Press the a key for the average of the differences.")
print("Press the m key for the mode of the differences.")
print("Press the h key for a histogram of the found differences.")
print("Press any other key to quit.")

while True:

  # Let's try some stats

    operationInput = input("Enter your option: ")

    if operationInput == "d":
        print(scoresArray)
    if operationInput == "a":
        # Get the mean of the array
        print("This is the average between v3.1 and v4.0 scores for the calculated ranges:")
        print(str(average_difference(scoresArray)))
    if operationInput == "h":
        print("This is the histogram of the differences")
        create_histogram(scoresArray)
    if operationInput == "m":
        # Get the average change, the mode
        print("This is the most common change for the calculated ranges:")
        print(str(mode_difference(scoresArray)))
    if operationInput == "q":
        break