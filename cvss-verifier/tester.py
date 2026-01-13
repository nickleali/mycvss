# Test simple functionality

# load libraries

import time
import os
import json
from bs4 import BeautifulSoup

# parsing loop for looking at an entire directory

"""
Reads each file and directory name in the given directory path
and prints them.

Args:
    directory_path (str): The path to the directory to be scanned.
"""

directory_path = "/workspaces/mycvss/cvss-verifier/reports/Cisco/"

if not os.path.exists(directory_path):
    print(f"Error: The directory '{directory_path}' does not exist.")
    
if not os.path.isdir(directory_path):
    print(f"Error: '{directory_path}' is not a directory.")
    
print(f"Listing contents of directory: {directory_path}\n")

try:
    # Get a list of all files and directories in the specified path
    files_and_dirs = os.listdir(directory_path)
    print("In the try loop")
    
    if not files_and_dirs:
        print("The directory is empty.")
    
    # start of the directory loop
    for item in files_and_dirs:
        print(item)

### Above this section should loop to read everything from a local directory

### Code below this block will process a single file in input_file and output a single file

        # Path to your HTML file
        # input_file = '/workspaces/mycvss/cvss-verifier/reports/Cisco/21084'
        input_file = directory_path + item

        # Derive output file name (replace .html or .htm with .json)
        base, ext = os.path.splitext(input_file)
        output_file = base + '.json'

        # Load and parse the HTML file
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()

        soup = BeautifulSoup(html_content, 'html.parser')

        attribute_names = [
            'Attack Vector (AV)',
            'Attack Complexity (AC)',
            'Privileges Required (PR)',
            'User Interaction (UI)',
            'Scope (S)',
            'Confidentiality (C)',
            'Integrity (I)',
            'Availability (A)'
        ]

        cve_data = {}

        cve_elements = soup.find_all(id=lambda x: x and x.startswith('colCveId-'))

        for cve_elem in cve_elements:
            cve_id = cve_elem.text.strip()
            idx = int(cve_elem['id'].split('-')[1])
            cve_data[cve_id] = {}
            for i, attr in enumerate(attribute_names):
                # row_num = idx * 8 + i # something wrong with the math here
                # keeping this in here so that I remember genAI makes mistakes
                row_num = idx + i
                cna_val = soup.find(id=f'colCnaVal-{row_num}')
                nist_val = soup.find(id=f'colNistVal-{row_num}')
                cna_value = cna_val.text.strip() if cna_val else None
                nist_value = nist_val.text.strip() if nist_val else None
                cve_data[cve_id][attr] = {
                    'CNA': cna_value,
                    'NIST': nist_value
                }

        # Save to JSON file
        with open(output_file, 'w', encoding='utf-8') as out_f:
            json.dump(cve_data, out_f, indent=2, ensure_ascii=False)

        print(f"CVEs extracted and saved to: {output_file}")

### End of single file processing block

### Below here continues the main loop and handles errors in directory reading 
except PermissionError:
        print(f"Error: Permission denied to access '{directory_path}'.")
except Exception as e:
        print(f"An unexpected error occurred: {e}")

