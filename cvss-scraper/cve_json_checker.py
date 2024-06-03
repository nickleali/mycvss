import json
import os
from pathlib import Path
import objectpath

# user_input = input('Input the directory with the CVE JSON.')

searchstring = "cvssV4_0"

user_input = "/home/kali/cvelistV5/cves/2024/0xxx"

directory = os.listdir(user_input)

# script to return various things about CVSS v4.0 from the CVE JSON


result = list(Path("/home/kali/cvelistV5/cves/2024").rglob("*.json"))

# print(result)

# first, a search for all CVSS v4.0 metrics and return them


for fname in result:
	if os.path.isfile(fname):
		# Full path
		f = open(fname)
		lines = f.readlines()
		
		vector_lines = []
		for i in range(len(lines)):
			#print(lines)
			if "CVSS:4.0" in lines[i]:
				vector_lines.append(lines[i].strip("\n"))
				print('Found v4 vectors in file %s' % fname)
				print(vector_lines)
		f.close()

