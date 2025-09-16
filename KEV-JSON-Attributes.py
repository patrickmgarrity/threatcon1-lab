import json
import csv
from datetime import datetime
from urllib.parse import urlparse

# Load JSON data from file
with open('vulncheck_known_exploited_vulnerabilities.json', 'r') as f:
    data = json.load(f)

# Define the CSV file headers
headers = [
    "cve", "vendorProject", "product", "shortDescription", "vulnerabilityName", 
    "required_action", "knownRansomwareCampaignUse", "vulncheck_xdb", 
    "vulncheck_reported_exploitation", "dueDate", "cisa_date_added", "date_added",
    "total_reference_links", "total_xdb_links", "total_reference_links_adjusted"
]

# Open the CSV file for writing
with open('vulncheck_kev.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(headers)
    
    # Iterate through JSON data and write rows to CSV
    for item in data:
        # Convert vulncheck_xdb to a string representation and count links
        vulncheck_xdb = ", ".join([str(x) for x in item.get("vulncheck_xdb", [])])
        total_xdb_links = len(item.get("vulncheck_xdb", []))
        
        # Find the first reported exploitation link based on the earliest date_added and count links
        reported_exploitations = item.get("vulncheck_reported_exploitation", [])
        total_reference_links = len(reported_exploitations)
        
        # Create a set to track unique URLs and handle shadowserver.org separately
        unique_urls = set()
        shadowserver_seen = False
        
        for exploitation in reported_exploitations:
            url = exploitation['url']
            domain = urlparse(url).netloc
            if 'shadowserver.org' in domain:
                if not shadowserver_seen:
                    shadowserver_seen = True
            else:
                unique_urls.add(url)
        
        # Adjust the total reference links count
        total_reference_links_adjusted = len(unique_urls) + (1 if shadowserver_seen else 0)
        
        if reported_exploitations:
            first_exploitation = min(reported_exploitations, key=lambda x: datetime.fromisoformat(x['date_added'].replace('Z', '')))
            vulncheck_reported_exploitation = f"{first_exploitation['url']} ({first_exploitation['date_added']})"
        else:
            vulncheck_reported_exploitation = ""
        
        row = [
            ", ".join(item.get("cve", [])),
            item.get("vendorProject", ""),
            item.get("product", ""),
            item.get("shortDescription", ""),
            item.get("vulnerabilityName", ""),
            item.get("required_action", ""),
            item.get("knownRansomwareCampaignUse", ""),
            vulncheck_xdb,
            vulncheck_reported_exploitation,
            item.get("dueDate", ""),
            item.get("cisa_date_added", ""),
            item.get("date_added", ""),
            total_reference_links,
            total_xdb_links,
            total_reference_links_adjusted
        ]
        csvwriter.writerow(row)
