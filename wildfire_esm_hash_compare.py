import pymssql
import hashlib
import sys
import os
import time
import argparse
from argparse import RawTextHelpFormatter
import requests
from xml.etree import ElementTree as ET
import re

starttime=time.time()
interval=0.0
server=''
user=''
password=''
database=''
malware_path = ''
grayware_path = ''
benign_path = ''
staging_directory = ''
api_key = ''
hash_file = ''

parser = argparse.ArgumentParser(add_help=True,
                    formatter_class=RawTextHelpFormatter,
                    description='Usage Example: \n\nwildfire_esm_hash_compare.py -i 30.0 -a localhost -u HC-HIDEOUT\Administrator -p MyPassw0rd -d TRAPSDB -m c:\FilesInspectedbyWildfire_Malware -b c:\FilesInspectedbyWildfire_Benign -s c:\FilesUploadedByCustomer -k YourWildFireAPIKey -w hashes.txt')

parser.add_argument("-i", action="store",
                    help="Interval that scans are ran.  Example:  30.0 equals 30 Seconds")

parser.add_argument("-a", action="store",
                    help="Host.  Example:  localhost, 192.168.0.10, 127.0.0.1")

parser.add_argument("-u", action="store",
                    help="Login with username")

parser.add_argument("-p", action="store",
                    help="Login with password")

parser.add_argument("-d", action="store",
                    help="Database Name (Case Sensitive)")

parser.add_argument("-m", action="store",
                    help="Malware Path.  Example:  c:\FilesInspectedbyWildfire_Malware")

parser.add_argument("-b", action="store",
                    help="Benign Path.  Example:  c:\FilesInspectedbyWildfire_Benign")

parser.add_argument("-g", action="store",
                    help="Grayware Path.  Example:  c:\FilesInspectedbyWildfire_Grayware")

parser.add_argument("-s", action="store",
                    help="Staging Directory.  Example:  c:\FilesUploadedByCustomer")

parser.add_argument("-k", action="store",
                    help="Staging Directory.  Example:  c:\FilesUploadedByCustomer")

parser.add_argument("-w", action="store",
                    help="Staging Directory.  Example:  c:\FilesUploadedByCustomer")

args = parser.parse_args()

if args.i:
    interval = float(args.i)
if args.a:
    server = args.a
if args.u:
    user = args.u
if args.p:
    password = args.p
if args.d:
    database = args.d
if args.m:
    malware_path = args.m
if args.b:
    benign_path = args.b
if args.g:
    grayware_path = args.g
if args.s:
    staging_directory = args.s
if args.k:
    api_key = args.k
if args.w:
    hash_file = args.w

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def analyze_and_move_files():
    global malware_path, benign_path, staging_directory, server, user, password, database
    try:
        for root, dirs, files in os.walk(r''+staging_directory+''):
            for file in files:
                hash_256 = sha256_checksum(os.path.join(root,file))
                conn = pymssql.connect(server=server, user=user, password=password, database=database)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult<>%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if hash_256 != esm_256_hash:
                        read_hashes = open(hash_file, 'r')
                        if re.findall(r''+hash_256+'', read_hashes.read()):
                            pass
                        else:
                            print "Sending to Wildfire to match hash", hash_256
                            hashes_not_in_esm = open(hash_file, "ab+")
                            hashes_not_in_esm.writelines(hash_256+'\n')
                            hashes_not_in_esm.close()
                        read_hashes.close()
                    elif wildfire_last_result == 1:
                        if hash_256 == esm_256_hash:
                            print "ESM Malware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(malware_path,file)):
                                os.remove(os.path.join(malware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                    elif wildfire_last_result == 2:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 5:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 3:
                        pass

                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult=%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 0:
                        if hash_256 == esm_256_hash:
                            print "ESM Benign Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(benign_path,file)):
                                os.remove(os.path.join(benign_path,file))
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                conn.close()

        for root, dirs, files in os.walk(r''+malware_path+''):
            for file in files:
                hash_256 = sha256_checksum(os.path.join(root,file))
                conn = pymssql.connect(server=server, user=user, password=password, database=database)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult<>%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 2:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 3:
                        pass
                    elif wildfire_last_result == 5:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 6:
                        pass

                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult=%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 0:
                        if hash_256 == esm_256_hash:
                            print "ESM Benign Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(benign_path,file)):
                                os.remove(os.path.join(benign_path,file))
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                conn.close()

        for root, dirs, files in os.walk(r''+benign_path+''):
            for file in files:
                hash_256 = sha256_checksum(os.path.join(root,file))
                conn = pymssql.connect(server=server, user=user, password=password, database=database)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult<>%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 1:
                        if hash_256 == esm_256_hash:
                            print "ESM Malware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(malware_path,file)):
                                os.remove(os.path.join(malware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                    elif wildfire_last_result == 2:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 3:
                        pass
                    elif wildfire_last_result == 5:
                        if hash_256 == esm_256_hash:
                            print "ESM Grayware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(grayware_path,file)):
                                os.remove(os.path.join(grayware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                    elif wildfire_last_result == 6:
                        pass

                conn.close()

        for root, dirs, files in os.walk(r''+grayware_path+''):
            for file in files:
                hash_256 = sha256_checksum(os.path.join(root,file))
                conn = pymssql.connect(server=server, user=user, password=password, database=database)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult<>%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 1:
                        if hash_256 == esm_256_hash:
                            print "ESM Malware Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(malware_path,file)):
                                os.remove(os.path.join(malware_path,file))
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                    elif wildfire_last_result == 3:
                        pass
                    elif wildfire_last_result == 6:
                        pass

                cursor.execute('SELECT * FROM ProcessHashesData WHERE LastWildfireResult=%s', '0')
                for row in cursor:
                    esm_256_hash = row[1]
                    wildfire_last_result = row[6]
                    if wildfire_last_result == 0:
                        if hash_256 == esm_256_hash:
                            print "ESM Benign Hash matches " + os.path.join(root,file), esm_256_hash, wildfire_last_result
                            if os.path.exists(os.path.join(benign_path,file)):
                                os.remove(os.path.join(benign_path,file))
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                            else:
                                os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                conn.close()

        files = {'apikey': (None, api_key),'file': (hash_file, open(hash_file, 'rb'))}
        if os.stat(hash_file).st_size != 0:
            xml_tree = ET.fromstring(requests.post('https://wildfire.paloaltonetworks.com/publicapi/get/verdicts', files=files).content)
            for item in xml_tree.iter("wildfire"):
                for item in xml_tree.iter("get-verdict-info"):
                    for root, dirs, files in os.walk(r''+staging_directory+''):
                        for file in files:
                            hash_256 = sha256_checksum(os.path.join(root,file))
                            if item.find("sha256").text == hash_256:
                                if item.find("verdict").text == '0':
                                    print "WildFire Benign Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(benign_path,file)):
                                        os.remove(os.path.join(benign_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                elif item.find("verdict").text == '1':
                                    print "WildFire Malware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(malware_path,file)):
                                        os.remove(os.path.join(malware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                elif item.find("verdict").text == '2':
                                    print "WildFire Grayware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(grayware_path,file)):
                                        os.remove(os.path.join(grayware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                else:
                                    pass
                    for root, dirs, files in os.walk(r''+benign_path+''):
                        for file in files:
                            hash_256 = sha256_checksum(os.path.join(root,file))
                            if item.find("sha256").text == hash_256:
                                if item.find("verdict").text == '1':
                                    print "WildFire Malware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(malware_path,file)):
                                        os.remove(os.path.join(malware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                elif item.find("verdict").text == '2':
                                    print "WildFire Grayware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(grayware_path,file)):
                                        os.remove(os.path.join(grayware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                else:
                                    pass
                    for root, dirs, files in os.walk(r''+grayware_path+''):
                        for file in files:
                            hash_256 = sha256_checksum(os.path.join(root,file))
                            if item.find("sha256").text == hash_256:
                                if item.find("verdict").text == '0':
                                    print "WildFire Benign Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(benign_path,file)):
                                        os.remove(os.path.join(benign_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                elif item.find("verdict").text == '1':
                                    print "WildFire Malware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(malware_path,file)):
                                        os.remove(os.path.join(malware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                else:
                                    pass
                    for root, dirs, files in os.walk(r''+malware_path+''):
                        for file in files:
                            hash_256 = sha256_checksum(os.path.join(root,file))
                            if item.find("sha256").text == hash_256:
                                if item.find("verdict").text == '0':
                                    print "WildFire Benign Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(benign_path,file)):
                                        os.remove(os.path.join(benign_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                elif item.find("verdict").text == '2':
                                    print "WildFire Grayware Hash matches " + os.path.join(root,file), hash_256
                                    if os.path.exists(os.path.join(grayware_path,file)):
                                        os.remove(os.path.join(grayware_path,file))
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                    else:
                                        os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                else:
                                    pass
        f = open(hash_file, 'r+')
        f.truncate()
        f.close()
    except IOError as e:
        print e
        conn.close()
        pass

    except Exception as e:
        print e
        conn.close()
        pass

    except:
        conn.close()
        pass

def execute_interval():
    global interval
    while True:
        analyze_and_move_files()
        time.sleep(interval - ((time.time() - starttime) % interval))

execute_interval()
