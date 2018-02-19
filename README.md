# Wildfire ESM Hash Comparison

This app was written for Palo Alto Networks to compare file hashes against Wildfire and move them to specific directories based on the verdict.  If the hash is not found in Wildfire, the file will be uploaded for analysis to get verdict.

## Install:
  
  Install Python2.7 on Windows Server where ESM is installed.  (https://github.com/BurntSushi/nfldb/wiki/Python-&-pip-Windows-installation)
  
  Download pymssql from here http://www.lfd.uci.edu/~gohlke/pythonlibs/#pymssql
  
  pip install pymssql‑2.1.3‑cp36‑cp36m‑win_amd64.whl
  
  pip install hashlib
  
  pip install requests

  pip install six
  
  pip install urllib3
  
## Usage:
```
usage: wildfire_hash_compare.py [-h] [-i I] [-m M] [-b B] [-g G]

               [-s S] [-k K] [-f F]

Usage Example: 

wildfire_hash_compare.py -i 30 -m c:\FilesInspectedbyWildfire_Malware -b c:\FilesInspectedbyWildfire_Benign -s c:\FilesUploadedByCustomer -k YourWildFireAPIKey -f hashes.txt

optional arguments:

  -h, --help  show this help message and exit
  
  -i I        Interval that scans are ran.  Example:  30.0 equals 30 Seconds

  -m M        Malware Path.  Example:  c:\FilesInspectedbyWildfire_Malware
  
  -b B        Benign Path.  Example:  c:\FilesInspectedbyWildfire_Benign
  
  -g G        Grayware Path.  Example:  c:\FilesInspectedbyWildfire_Grayware
  
  -s S        Staging Directory.  Example:  c:\FilesUploadedByCustomer
  
  -k K        Your Wildfire API Key
  
  -f F        filename to store hashes.  Example:  hashes.txt
  ```
