import os
import re


def translate():
    with open(r'C:\Users\guo\Desktop\key.txt','r') as loc:
        content=loc.read()
    name_list=re.findall("name: '([a-zA-Z]*?)'",content,re.S)
    a=str(name_list).replace("'","")
    print(a)

if __name__=='__main__':
    translate();