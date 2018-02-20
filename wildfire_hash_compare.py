import hashlib
import sys
import os
import time
import argparse
from argparse import RawTextHelpFormatter
import requests
from xml.etree import ElementTree as ET
import re
import logging
from logging import getLogger
from logging.handlers import RotatingFileHandler as RFHandler
from threading import Thread

logfilesize = 1048576
numberofbackups = 3
starttime=time.time()
interval=0.0
malware_path = ''
grayware_path = ''
benign_path = ''
staging_directory = ''
api_key = ''
hash_file = ''
directories_to_be_scanned = []
wildfire_checked_list=[]
file_hashes = []
hash_and_file = []
file_to_be_uploaded = []
uploaded_files = []
app_root = os.path.dirname(os.path.abspath(__file__))

def setup_logging_to_file(logfile):
    try:
        logging.basicConfig(filename=logfile,
                        filemode='a',
                        level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
        log = getLogger()
        rotateHandler = RFHandler(logfile, "a", logfilesize, numberofbackups)
        log.addHandler(rotateHandler)

    except Exception, e:
        log_exception(e)
        return str(e)

def extract_function_name():
    try:
        tb = sys.exc_info()[-1]
        stk = traceback.extract_tb(tb, 1)
        fname = stk[0][3]
        return fname

    except Exception, e:
        log_exception(e)
        return str(e)

def log_exception(e):
    try:
        logging.error(
            "Function {function_name} raised {exception_class} ({exception_docstring}): {exception_message}".format(
                function_name=extract_function_name(),
                exception_class=e.__class__,
                exception_docstring=e.__doc__,
                exception_message=e.message))

    except Exception, e:
        log_exception(e)
        return str(e)

t1 = Thread(target=setup_logging_to_file(app_root+'/messages.log'))
t1.start()

parser = argparse.ArgumentParser(add_help=True,
                    formatter_class=RawTextHelpFormatter,
                    description='Usage Example: \n\nwildfire_hash_compare.py -i 30 -m c:\FilesInspectedbyWildfire_Malware -b c:\FilesInspectedbyWildfire_Benign -s c:\FilesUploadedByCustomer -k YourWildFireAPIKey -f hashes.txt')

parser.add_argument("-i", action="store",
                    help="Interval that scans are ran.  Example:  30.0 equals 30 Seconds")

parser.add_argument("-m", action="store",
                    help="Malware Path.  Example:  c:\FilesInspectedbyWildfire_Malware")

parser.add_argument("-b", action="store",
                    help="Benign Path.  Example:  c:\FilesInspectedbyWildfire_Benign")

parser.add_argument("-g", action="store",
                    help="Grayware Path.  Example:  c:\FilesInspectedbyWildfire_Grayware")

parser.add_argument("-s", action="store",
                    help="Staging Directory.  Example:  c:\FilesUploadedByCustomer")

parser.add_argument("-k", action="store",
                    help="API Key")

parser.add_argument("-f", action="store",
                    help="Hash Filename to store Hashes for Wildfire Matching.  Example:  hashes.txt")

args = parser.parse_args()

if args.i:
    interval = float(args.i)
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
if args.f:
    hash_file = args.f

directories_to_be_scanned.extend((staging_directory, benign_path, grayware_path, malware_path))

def empty_file():
    global hash_file
    try:
        if os.path.exists(hash_file):
            f = open(hash_file, 'r+')
            f.truncate()
            f.close()
        else:
            f= open(hash_file, "w+")
            f.close()

    except IOError, e:
        log_exception(e)
        print e
        f.close()
        pass

    except Exception, e:
        log_exception(e)
        print e
        f.close()
        pass

    except:
        log_exception("Unexpected error: {0}".format(sys.exc_info()[0]))
        print "Unexpected error:", sys.exc_info()[0]
        f.close()
        pass

empty_file()

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def analyze_and_move_files():
    global malware_path, benign_path, staging_directory, directories_to_be_scanned, file_to_be_uploaded, uploaded_files
    try:
        empty_file()
        for directory in directories_to_be_scanned:
            for root, dirs, files in os.walk(r''+directory+''):
                for file in files:
                    hash_256 = sha256_checksum(os.path.join(root,file))
                    read_hashes = open(hash_file, 'r')
                    if re.findall(r''+hash_256+'', read_hashes.read()):
                        pass
                    else:
                        hashes = open(hash_file, "ab+")
                        hashes.writelines(hash_256+'\n')
                        hashes.close()
                    read_hashes.close()

        if os.stat(hash_file).st_size != 0:
            files = {'apikey': (None, api_key),'file': (hash_file, open(hash_file, 'rb'))}
            xml_tree = ET.fromstring(requests.post('https://wildfire.paloaltonetworks.com/publicapi/get/verdicts', files=files).content)
            for item in xml_tree.iter("wildfire"):
                for item in xml_tree.iter("get-verdict-info"):
                    for directory in directories_to_be_scanned:
                        for root, dirs, files in os.walk(r''+directory+''):
                            for file in files:
                                hash_256 = sha256_checksum(os.path.join(root,file))
                                if item.find("sha256").text == hash_256:
                                    if item.find("verdict").text == '0':
                                        if directory == benign_path:
                                            pass
                                        else:
                                            if hash_256 in wildfire_checked_list:
                                                read_hashes = open(hash_file, 'r+')
                                                if re.findall(r''+hash_256+'', read_hashes.read()):
                                                    print >>read_hashes, hash_256[:-1]
                                                    logging.info("Removed {0} from {1}".format(hash_256, os.path.join(read_hashes,file)))
                                                    print "Removed ", hash_256, "from ", os.path.join(read_hashes,file)
                                            else:
                                                logging.info("WildFire Benign Hash matches {0} {1}".format(os.path.join(root,file), hash_256))
                                                print "WildFire Benign Hash matches " + os.path.join(root,file), hash_256
                                                if os.path.join(root,file) in uploaded_files:
                                                    uploaded_files.remove(os.path.join(root,file))
                                                if os.path.exists(os.path.join(benign_path,file)):
                                                    os.remove(os.path.join(benign_path,file))
                                                    os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                                else:
                                                    os.rename(os.path.join(root,file), os.path.join(benign_path,file))
                                                wildfire_checked_list.append(hash_256)
                                    elif item.find("verdict").text == '1':
                                        if directory == malware_path:
                                            pass
                                        else:
                                            if hash_256 in wildfire_checked_list:
                                                read_hashes = open(hash_file, 'r+')
                                                if re.findall(r''+hash_256+'', read_hashes.read()):
                                                    print >>read_hashes, hash_256[:-1]
                                                    logging.info("Removed {0} from {1}".format(hash_256, os.path.join(read_hashes,file)))
                                                    print "Removed ", hash_256, "from ", os.path.join(read_hashes,file)
                                            else:
                                                logging.info("WildFire Malware Hash matches {0} {1}".format(os.path.join(root,file), hash_256))
                                                print "WildFire Malware Hash matches " + os.path.join(root,file), hash_256
                                                if os.path.join(root,file) in uploaded_files:
                                                    uploaded_files.remove(os.path.join(root,file))
                                                if os.path.exists(os.path.join(malware_path,file)):
                                                    os.remove(os.path.join(malware_path,file))
                                                    os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                                else:
                                                    os.rename(os.path.join(root,file), os.path.join(malware_path,file))
                                                wildfire_checked_list.append(hash_256)
                                    elif item.find("verdict").text == '2':
                                        if directory == grayware_path:
                                            pass
                                        else:
                                            if hash_256 in wildfire_checked_list:
                                                read_hashes = open(hash_file, 'r+')
                                                if re.findall(r''+hash_256+'', read_hashes.read()):
                                                    print >>read_hashes, hash_256[:-1]
                                                    logging.info("Removed {0} from {1}".format(hash_256, os.path.join(read_hashes,file)))
                                                    print "Removed ", hash_256, "from ", os.path.join(read_hashes,file)
                                            else:
                                                logging.info("WildFire Grayware Hash matches {0} {1}".format(os.path.join(root,file), hash_256))
                                                print "WildFire Grayware Hash matches " + os.path.join(root,file), hash_256
                                                if os.path.join(root,file) in uploaded_files:
                                                    uploaded_files.remove(os.path.join(root,file))
                                                if os.path.exists(os.path.join(grayware_path,file)):
                                                    os.remove(os.path.join(grayware_path,file))
                                                    os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                                else:
                                                    os.rename(os.path.join(root,file), os.path.join(grayware_path,file))
                                                wildfire_checked_list.append(hash_256)
                                    elif item.find("verdict").text == '-100':
                                        logging.info("{0} with the hash Value - {1} is pending.  The sample exists, but there is currently no verdict.".format(file, item.find("sha256").text))
                                        print file, "with the hash Value -", item.find("sha256").text, "is pending.  The sample exists, but there is currently no verdict."
                                    elif item.find("verdict").text == '-101':
                                        logging.info("{0} with the hash Value - {1} There was an error.".format(file, item.find("sha256").text))
                                        print file, "with the hash Value -", item.find("sha256").text, "There was an error."
                                    elif item.find("verdict").text == '-102':
                                        if file_to_be_uploaded in uploaded_files:
                                            logging.info("Skipped {0}.  File has been Uploaded to Wildfire.".format(file_to_be_uploaded))
                                            print "Skipped", file_to_be_uploaded, "File has been Uploaded to Wildfire."
                                            pass
                                        else:
                                            file_to_be_uploaded = os.path.join(root,file)
                                            files = {'apikey': (None, api_key), 'file': (open(file_to_be_uploaded, 'rb'))}
                                            xml_tree = ET.fromstring(requests.post('https://wildfire.paloaltonetworks.com/publicapi/submit/file', files=files).content)
                                            uploaded_files.append(file_to_be_uploaded)
                                            logging.info("{0} with the hash Value - {1} did not match.  Verdict was unknown. Cannot find sample record in the database.  Uploading to Wildfire.".format(file, item.find("sha256").text))
                                            print file, "with the hash Value -", item.find("sha256").text, "did not match.  Verdict was unknown. Cannot find sample record in the database.  Uploading to Wildfire."
                                    elif item.find("verdict").text == '-103':
                                        logging.info("{0} with the hash Value - {1} is an invalid hash value.".format(file, item.find("sha256").text))
                                        print file, "with the hash Value -", item.find("sha256").text, "is an invalid hash value."
                                else:
                                    continue
        else:
            pass
        empty_file()
    except IOError, e:
        log_exception(e)
        print e
        pass

    except Exception, e:
        log_exception(e)
        print e
        pass

    except:
        log_exception("Unexpected error: {0}".format(sys.exc_info()[0]))
        print "Unexpected error:", sys.exc_info()[0]
        pass

def execute_interval():
    global interval
    while True:
        analyze_and_move_files()
        time.sleep(interval - ((time.time() - starttime) % interval))

t2 = Thread(target=execute_interval)
t2.start()
