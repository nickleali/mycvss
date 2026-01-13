# These functions should take the data out of a CVMAP function and prep it to send to SQL. Work to just strip out the values and get them ready for SQL or similar.

# Prompt: Process the provided HTML document and 

# Function

# HTML elements

'''
The provided document text below in HTML format contains a list of security vulnerabilities listed by CVE. Each CVE is in a HTML element with a ID of colCveId, for example, the id="colCveId-0" element is the first CVE in the page. 

The rows following each CVE are numbered like wldRow1, to a total of 8, so the values are grouped in eight. Iterate the rows in groups of 8 and store in a variable. Each value is paried, and there is one each for CNA (like id="colCnaVal-1") and NIST (id="colNistVal-1")

Given the description of this document, create a python script that will load this file from a local folder, process the document, and store in a variable for each CVE the value of both the CNA and NIST values for Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I), and Availability (A).
'''

from bs4 import BeautifulSoup

# Load the HTML file
with open('path/to/your/file.html', 'r', encoding='utf-8') as f:
    html_content = f.read()

soup = BeautifulSoup(html_content, 'html.parser')

# CVSS Attribute names, in the expected order
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

# Find all CVE elements by their ID pattern
cve_elements = soup.find_all(id=lambda x: x and x.startswith('colCveId-'))

for cve_elem in cve_elements:
    # Extract CVE ID (e.g., CVE-2023-XXXX)
    cve_id = cve_elem.text.strip()
    # The numeric index for this CVE (e.g., colCveId-0 -> 0)
    idx = cve_elem['id'].split('-')[1]
    
    # Prepare to store CNA/NIST values for this CVE
    cve_data[cve_id] = {}
    
    for i, attr in enumerate(attribute_names):
        row_num = int(idx) * 8 + i  # Calculate absolute row number
        cna_val = soup.find(id=f'colCnaVal-{row_num}')
        nist_val = soup.find(id=f'colNistVal-{row_num}')
        cna_value = cna_val.text.strip() if cna_val else None
        nist_value = nist_val.text.strip() if nist_val else None
        cve_data[cve_id][attr] = {
            'CNA': cna_value,
            'NIST': nist_value
        }

# Example: Print results
for cve_id, attrs in cve_data.items():
    print(f"{cve_id}:")
    for attr, values in attrs.items():
        print(f"  {attr}: CNA={values['CNA']}, NIST={values['NIST']}")