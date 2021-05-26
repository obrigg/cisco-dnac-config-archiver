"""
This program will leverage Cisco DNA Center's configuration archive API
(Avaialble in version 2.1.x and above) in order to save a local, password
protected ZIP file with the configuration of the network devices.

If the provided DNAC password is sufficient for the password rules - it will
be used. Otherwise, the user will be prompted to enter a new password.
"""

__author__ = "Oren Brigg"
__author_email__ = "obrigg@cisco.com"
__copyright__ = "Copyright (c) 2021 Cisco Systems, Inc."

import os
import time
import json
import requests
from dnacentersdk import api
from pprint import pprint
from datetime import datetime
requests.packages.urllib3.disable_warnings()

DNAC=os.environ.get('DNAC','sandboxdnac.cisco.com')
DNAC_USER=os.environ.get('DNAC_USER','devnetuser')
DNAC_PASSWORD=os.environ.get('DNAC_PASSWORD','Cisco123!')
DNAC_PORT=os.environ.get('DNAC_PORT',443)
DNAC_VERSION="2.1.2"

def is_password_ok(password: str):
    '''
    Checking the password against DNAC's policy for ZIP file password.
    The function will return True if the password is adequite and
    False in case it is not.
    '''
    if len(password) < 8:
        return (False)
    hasLower = False
    hasUpper = False
    hasSpecial = False
    for c in password:
        if c.islower():
            hasLower = True
        if c.isupper():
            hasUpper = True
        if c in "-=\\;,./~!@#$%^&*()_+{}[]|:?":
            hasSpecial = True
    if hasLower and hasUpper and hasSpecial:
        return(True)
    else:
        return(False)

if is_password_ok(DNAC_PASSWORD) == True:
    zip_password = DNAC_PASSWORD
else:
    print("DNAC's password is insuffiecient. \
        \nMin password length is 8 and it should contain at least one \
lower case letter, one uppercase letter, \
    \none digit and one special characters from -=\\;,./~!@#$%^&*()_+{}[]|:?\n")
    zip_password = input("Enter new password: ")

dnac = api.DNACenterAPI(username=DNAC_USER,
                            password=DNAC_PASSWORD,
                            base_url="https://" + DNAC + ":" + str(DNAC_PORT),
                            version=DNAC_VERSION,
                            verify=False)

devices = dnac.devices.get_device_list()['response']
device_list = []
families_to_ignore = ["Meraki", "Unified AP", "Sensor", "Third Party"]
for device in devices:
    if any(item in device['family'] for item in families_to_ignore):
        pass
    else:
        device_list.append(device['id'])

#dnac.configuration_archive.export_device_configurations()
url = f"https://{DNAC}:{DNAC_PORT}/dna/intent/api/v1/network-device-archive/cleartext"
headers = {'Content-Type': 'application/json',
            'x-auth-token': dnac.access_token}
body = {'deviceId': device_list, 'password': 'Cisco123!'}
response = requests.post(url=url, headers=headers, data=json.dumps(body), verify=False)

if response.status_code != 202:
    print(f"Error: {response.text}")
    raise Exception(f"Error: {response.text}")

taskId = response.json()['response']['taskId']
time.sleep(2)
taskStatus = dnac.task.get_task_by_id(taskId)['response']

while taskStatus['progress'] != "Device configuration Successfully exported as password protected ZIP.":
    print(f"Waiting for task {taskId} to complete..")
    if taskStatus['isError'] == True:
        print(f"Error: {taskStatus}")
        raise Exception(f"Error: {taskStatus}")
    time.sleep(3)
    taskStatus = dnac.task.get_task_by_id(taskId)['response']

filename = f'archive_{datetime.utcnow().isoformat()[:16].replace(":", "-")}.zip'
file_url = f"https://{DNAC}:{DNAC_PORT}{taskStatus['additionalStatusURL']}"
file = requests.get(file_url, headers=headers, verify=False)

with open(filename, 'wb') as f:
    f.write(file.content)

print(f"\n\nDone. File {filename} was created.\n\n")