# script to scan contents of files in a directory for CVSS scores and compare them

# store those and check against them


import json
import os
from pathlib import Path
import objectpath

# user_input = input('Input the directory with the CVE JSON.')

searchstring = "cvssV4_0"

user_input = "/home/kali/cvelistV5/cves/2024/0xxx"

directory = os.listdir(user_input)

# script to return various things about CVSS v4.0 from the CVE JSON

# get the list of all the files to check
result = list(Path("/home/kali/cvelistV5/cves/2024").rglob("*.json"))

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
            if "CVSS:4.0" in lines[i]:
                vector_lines.append(lines[i].strip("\n"))
                print('Found CVSS vectors in file %s' % fname)
                #print(vector_lines)
                for i in range(len(lines)):
                    if "CVSS:3.1" in lines[i]:
                        vector_lines.append(lines[i].strip("\n"))
        f.close()
        print(vector_lines)

