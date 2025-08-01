import requests
import json
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv
import os 

# Disable only InsecureRequestWarning warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
load_dotenv()
token = os.getenv('NETBOX_TOKEN')

base_url = "https://netbox.cselab.io/api"
headers = {"Authorization": f"Token {token}"}

# Create optimized session
session = requests.Session()
session.headers.update(headers)
session.verify = False

retry_strategy = Retry(total=3, backoff_factor=0.3)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
session.mount("https://", adapter)

def fetch_cables_page(offset, limit=50):
    params = {
        "offset": offset,
        "limit": limit,
        "status": "connected",  # Server-side filtering if supported
        # Add more filters here if API supports them
    }
    response = session.get(f"{base_url}/dcim/cables", params=params)
    response.raise_for_status()
    return response.json()

# Get total count
first_response = fetch_cables_page(0, 1)
total_count = first_response["count"]

# Generate all offsets
limit = 50
offsets = list(range(0, total_count, limit))

cables = []
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(fetch_cables_page, offset, limit) for offset in offsets]
    for future in concurrent.futures.as_completed(futures):
        try:
            data = future.result()
            # Apply remaining client-side filters if needed
            filtered_cables = [
                                cable for cable in data["results"]
                                if cable["type"] != "" and cable["type"] not in ("console", "power")
                            ]
            cables.extend(filtered_cables)
        except Exception as e:
            print(f"Error: {e}")

with open("response.json", "w") as json_file:
    json.dump(cables, json_file, indent=2)