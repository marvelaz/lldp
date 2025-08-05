import requests
import os 
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning

# Disable only InsecureRequestWarning warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

load_dotenv()
token = os.getenv('NETBOX_TOKEN')

url = "https://netbox.cselab.io/api/ipam/ip-addresses/"
headers = {
    "Authorization": f"Token {token}",
    "Content-Type": "application/json"
}

def get_device_hostname(ip):
    params = {"address": ip}
    response = requests.get(url, headers=headers, params=params, verify=False)
    data = response.json()
    device_name = data['results'][0]['assigned_object']['device']['name']
    return(device_name)

ips = ["10.10.10.11", "10.10.10.12", "10.10.10.16"]

for ip in ips:
    c = get_device_hostname(ip)
    print(c)


