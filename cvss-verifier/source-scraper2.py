import json
import csv
import os

def parse_cvss_vector(vector_string):
    """
    Parses a CVSS v3.1 vector string into a dictionary of metric-value pairs.
    Example: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    Returns: {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N'}
    """
    metrics = {}
    if not vector_string or not vector_string.startswith("CVSS:3.1/"):
        return metrics

    parts = vector_string.split('/')[1:] # Skip "CVSS:3.1"
    for part in parts:
        if ':' in part:
            key, value = part.split(':', 1)
            metrics[key] = value
    return metrics

def compare_cvss_vectors_detail(nvd_vector_str, psirt_vector_str):
    """
    Compares two CVSS v3.1 vector strings and returns a string detailing differences.
    """
    nvd_metrics = parse_cvss_vector(nvd_vector_str)
    psirt_metrics = parse_cvss_vector(psirt_vector_str)

    differences = []
    
    # Get all unique metric keys from both dictionaries
    all_metric_keys = sorted(list(set(nvd_metrics.keys()) | set(psirt_metrics.keys())))

    for key in all_metric_keys:
        nvd_val = nvd_metrics.get(key, "N/A") # Use "N/A" if metric is missing from one
        psirt_val = psirt_metrics.get(key, "N/A")

        if nvd_val != psirt_val:
            differences.append(f"{key}: NVD={nvd_val}, PSIRT={psirt_val}")
    
    if differences:
        return "; ".join(differences)
    else:
        return "No specific differences found (should not happen if overall vectors are different)"


def process_cve_json(file_path):
    """
    Processes a JSON file containing CVE data, extracts CVSS vector strings
    from nvd@nist.gov and psirt@cisco.com sources, compares them,
    and stores the vectors along with their comparison result and detailed differences.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list of dictionaries, where each dictionary contains
              'cve_id', 'nvd_vector', 'psirt_vector', 'comparison_result',
              and 'detailed_differences' for CVEs that have both sources.
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
            comparison_result = "Same"
            detailed_differences = ""

            if nvd_vector != psirt_vector:
                comparison_result = "Different"
                detailed_differences = compare_cvss_vectors_detail(nvd_vector, psirt_vector)
            
            cvss_vector_comparisons.append({
                "cve_id": cve_data.get('id'),
                "nvd_vector": nvd_vector,
                "psirt_vector": psirt_vector,
                "comparison_result": comparison_result,
                "detailed_differences": detailed_differences
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
    # Ensure 'detailed_differences' is included if present
    fieldnames = list(data_list[0].keys()) 

    try:
        with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader() # Write the header row
            for row in data_list:
                writer.writerow(row) # Write each dictionary as a row
        print(f"Data successfully saved to '{output_csv_file}'")
    except IOError as e:
        print(f"Error writing to CSV file '{output_csv_file}': {e}")


# Save the dummy JSON content to a file
# file_name = "/workspaces/mycvss/cve/nvd/2023/nvdcve-2.0-2023.json"

# Define the input JSON file name
input_json_file = "/workspaces/mycvss/cve/nvd/2025/nvdcve-2.0-2025.json"
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
        if entry['detailed_differences']:
            print(f"  Detailed Differences: {entry['detailed_differences']}")
        print("-" * 30)
else:
    print("No CVSS vector pairs found with both NVD and PSIRT sources for comparison.")