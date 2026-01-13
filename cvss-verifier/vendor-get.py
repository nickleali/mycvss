import requests
from bs4 import BeautifulSoup
import re

def get_vendor_name_from_nvd_report(url):
    """
    Fetches a NVD CVSS report webpage and extracts the vendor name.

    The vendor name is expected to be found in the page body, after
    "CVSS v3.1 Statistics for" and before the date (which is preceded by "as of").

    Args:
        url (str): The URL of the NVD CVSS report page.

    Returns:
        str: The extracted vendor name, or None if it cannot be found.
    """
    try:
        # Fetch the content of the URL
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the URL {url}: {e}")
        return None

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # The vendor name is in the page body. We'll search the entire text content
    # of the body for the specific pattern.
    # The pattern looks for "CVSS v3.1 Statistics for " followed by any characters (non-greedy)
    # up to " as of ". The captured group (.*?) will be our vendor name.
    pattern = re.compile(r"CVSS v3\.1 Statistics for (.*?) as of ")

    # Get all text from the body, stripping whitespace and joining with spaces
    body_text = soup.body.get_text(separator=" ", strip=True)

    # Search for the pattern in the extracted body text
    match = pattern.search(body_text)

    if match:
        vendor_name = match.group(1).strip()
        return vendor_name
    else:
        # As a fallback, sometimes the title tag might contain this information
        if soup.title:
            title_match = pattern.search(soup.title.string)
            if title_match:
                return title_match.group(1).strip()
        
        print("Vendor name pattern not found in the page content or title.")
        return None

# --- Example Usage ---
if __name__ == "__main__":
    target_url = "https://nvd.nist.gov/vuln/cvmap/report/21190"
    vendor = get_vendor_name_from_nvd_report(target_url)

    if vendor:
        print(f"The vendor name found on the page is: {vendor}")
    else:
        print(f"Could not determine the vendor name from {target_url}.")