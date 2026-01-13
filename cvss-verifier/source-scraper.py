'''
Maybe we can just go back to the NVD and CVE program source and not worry about looking at the reports.

How big of a lift is it to just look at every CVE and record all the CVSS scores?

We need to check where the NVD score it, versus the vendor. 

Let's figure out a prompt for CIRCUIT.
'''

'''
CIRCUIT prompt for JSON processing

The following is a sample of JSON: 

{
  "resultsPerPage" : 38902,
  "startIndex" : 0,
  "totalResults" : 38902,
  "format" : "NVD_CVE",
  "version" : "2.0",
  "timestamp" : "2026-01-01T03:00:19.6486366",
  "vulnerabilities" : [ {
    "cve" : {
      "id" : "CVE-2024-0069",
      "sourceIdentifier" : "security@hypr.com",
      "published" : "2023-11-28T00:15:07.140",
      "lastModified" : "2023-11-28T00:15:07.140",
      "vulnStatus" : "Rejected",
      "cveTags" : [ ],
      "descriptions" : [ {
        "lang" : "en",
        "value" : "Rejected reason: This CVE ID was unused by the CNA."
      } ],
      "metrics" : { },
      "references" : [ ]
    }
  }, {
    "cve" : {
      "id" : "CVE-2024-20251",
      "sourceIdentifier" : "psirt@cisco.com",
      "published" : "2024-01-17T17:15:11.350",
      "lastModified" : "2024-11-21T08:52:06.593",
      "vulnStatus" : "Modified",
      "cveTags" : [ ],
      "descriptions" : [ {
        "lang" : "en",
        "value" : "A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to perform a stored cross-site scripting (XSS) attack against a user of the interface on an affected device. This vulnerability exists because the web-based management interface does not properly validate user-supplied input. An attacker could exploit this vulnerability by injecting malicious code into specific pages of the interface. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information."
      }, {
        "lang" : "es",
        "value" : "Una vulnerabilidad en la interfaz de administración basada en web de Cisco Identity Services Engine (ISE) podría permitir que un atacante remoto autenticado realice un ataque de cross site scripting (XSS) almacenado contra un usuario de la interfaz en un dispositivo afectado. Esta vulnerabilidad existe porque la interfaz de administración basada en web no valida adecuadamente la entrada proporcionada por el usuario. Un atacante podría aprovechar esta vulnerabilidad inyectando código malicioso en páginas específicas de la interfaz. Una explotación exitoso podría permitir al atacante ejecutar código de script arbitrario en el contexto de la interfaz afectada o acceder a información confidencial basada en el navegador."
      } ],
      "metrics" : {
        "cvssMetricV31" : [ {
          "source" : "psirt@cisco.com",
          "type" : "Secondary",
          "cvssData" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "baseScore" : 4.8,
            "baseSeverity" : "MEDIUM",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "HIGH",
            "userInteraction" : "REQUIRED",
            "scope" : "CHANGED",
            "confidentialityImpact" : "LOW",
            "integrityImpact" : "LOW",
            "availabilityImpact" : "NONE"
          },
          "exploitabilityScore" : 1.7,
          "impactScore" : 2.7
        }, {
          "source" : "nvd@nist.gov",
          "type" : "Primary",
          "cvssData" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "baseScore" : 5.4,
            "baseSeverity" : "MEDIUM",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "LOW",
            "userInteraction" : "REQUIRED",
            "scope" : "CHANGED",
            "confidentialityImpact" : "LOW",
            "integrityImpact" : "LOW",
            "availabilityImpact" : "NONE"
          },
          "exploitabilityScore" : 2.3,
          "impactScore" : 2.7
        } ]
      },

Create a python script that will process a file containing JSON formatted in this way. Store the values of CVSS vectors found in the vectorString value, matching both where 
the "source" : "nvd@nist.gov" and "source" : "psirt@cisco.com", and store each pair of CVSS metrics in a variable for later use. Unless both source for NVD and psirt@cisco.com are found, 
do not store the values.

'''

# Save the dummy JSON content to a file
# file_name = "/workspaces/mycvss/cve/nvd/2023/nvdcve-2.0-2023.json"

import json
import csv
import os # Import os module to handle file paths

def process_cve_json(file_path):
    """
    Processes a JSON file containing CVE data, extracts CVSS vector strings
    from nvd@nist.gov and psirt@cisco.com sources, compares them,
    and stores the vectors along with their comparison result.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list of dictionaries, where each dictionary contains
              'cve_id', 'nvd_vector', 'psirt_vector', and 'comparison_result'
              for CVEs that have both sources.
    """
    cvss_vector_comparisons = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{file_path}'. Please check file format.")
        return []

    for vulnerability_entry in data.get('vulnerabilities', []):
        cve_data = vulnerability_entry.get('cve', {})
        metrics = cve_data.get('metrics', {})
        cvss_metric_v31 = metrics.get('cvssMetricV31', [])

        nvd_vector = None
        psirt_vector = None

        for metric in cvss_metric_v31:
            source = metric.get('source')
            cvss_data = metric.get('cvssData', {})
            vector_string = cvss_data.get('vectorString')

            if source == 'nvd@nist.gov' and vector_string:
                nvd_vector = vector_string
            elif source == 'psirt@cisco.com' and vector_string:
                psirt_vector = vector_string
        
        # Only store the pair and compare if both NVD and PSIRT vectors were found
        if nvd_vector and psirt_vector:
            comparison_result = "Same" if nvd_vector == psirt_vector else "Different"
            
            cvss_vector_comparisons.append({
                "cve_id": cve_data.get('id'),
                "nvd_vector": nvd_vector,
                "psirt_vector": psirt_vector,
                "comparison_result": comparison_result
            })
    
    return cvss_vector_comparisons

def save_to_csv(data_list, output_csv_file):
    """
    Saves a list of dictionaries to a CSV file.

    Args:
        data_list (list): A list of dictionaries, where each dictionary
                          represents a row in the CSV.
        output_csv_file (str): The path to the output CSV file.
    """
    if not data_list:
        print("No data to save to CSV.")
        return

    # Get header names from the keys of the first dictionary
    fieldnames = data_list[0].keys()

    try:
        with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader() # Write the header row
            for row in data_list:
                writer.writerow(row) # Write each dictionary as a row
        print(f"Data successfully saved to '{output_csv_file}'")
    except IOError as e:
        print(f"Error writing to CSV file '{output_csv_file}': {e}")


# Define the input JSON file name
input_json_file = "/workspaces/mycvss/cve/nvd/2020/nvdcve-2.0-2020.json"
# Define the output CSV file name based on the input JSON file name
output_csv_file = os.path.splitext(input_json_file)[0] + ".csv"

# Process the JSON file to extract and compare vectors
extracted_comparisons = process_cve_json(input_json_file)

# Save the results to a CSV file
save_to_csv(extracted_comparisons, output_csv_file)

if extracted_comparisons:
    print("\n--- Console Output of Extracted Comparisons ---")
    for entry in extracted_comparisons:
        print(f"CVE ID: {entry['cve_id']}")
        print(f"  NVD Vector: {entry['nvd_vector']}")
        print(f"  PSIRT Vector: {entry['psirt_vector']}")
        print(f"  Comparison Result: {entry['comparison_result']}")
        print("-" * 30)
else:
    print("No CVSS vector pairs found with both NVD and PSIRT sources for comparison.")