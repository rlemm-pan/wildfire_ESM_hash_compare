# Wildfire ESM Hash Comparison

This app was written for Palo Alto Networks Traps Endpoint Security Manager to compare uploaded file hashes against the ESM Database and move them to specific directories based on the verdict from the ESM database.  If the hash is not found in the ESM Database, an attempt will be made to match the hash in Wildfire to get a verdict and move the file to the appropriate directory.

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
usage: test.py [-h] [-i I] [-a A] [-u U] [-p P] [-d D] [-m M] [-b B] [-g G]

               [-s S] [-k K] [-w W]

Usage Example: 

wildfire_esm_hash_compare.py -i 30.0 -a localhost -u HC-HIDEOUT\Administrator -p MyPassw0rd -d TRAPSDB -m c:\FilesInspectedbyWildfire_Malware -b c:\FilesInspectedbyWildfire_Benign -s c:\FilesUploadedByCustomer -k YourWildFireAPIKey -w hashes.txt

optional arguments:

  -h, --help  show this help message and exit
  
  -i I        Interval that scans are ran.  Example:  30.0 equals 30 Seconds
  
  -a A        Host.  Example:  localhost, 192.168.0.10, 127.0.0.1
  
  -u U        Login with username
  
  -p P        Login with password
  
  -d D        Database Name (Case Sensitive)
  
  -m M        Malware Path.  Example:  c:\FilesInspectedbyWildfire_Malware
  
  -b B        Benign Path.  Example:  c:\FilesInspectedbyWildfire_Benign
  
  -g G        Grayware Path.  Example:  c:\FilesInspectedbyWildfire_Grayware
  
  -s S        Staging Directory.  Example:  c:\FilesUploadedByCustomer
  
  -k K        Your Wildfire API Key
  
  -w W        filename to store hashes.  Example:  hashes.txt
  ```
