import json
import os
import re
import time

import requests
from bs4 import BeautifulSoup

downloadedList=[]
prefix="https://mcfp.felk.cvut.cz/publicDatasets"

class Link:
    link=""
    size=""
    def __init__(self,link,size):
        self.link=link
        self.size=size
    def __str__(self):
        return  f'[{self.link},{self.size}]'

    def dict(self):
        return {"link":self.link,"size":self.size}
def getdownloadedList(dir):
    for file in os.listdir(dir):
        downloadedList.append(file)
    print('downloaded_list:',downloadedList)
def getApis():
    getdownloadedList("D:\lisa_v1\pcap")
    names=getDirectoryNames()
    apis=getPcapNamesNew(names)
    count = 0
    for api in apis:
        print(f'show {api.link} --size={api.size}')
        if (not api.size.endswith('G') ):
            print(f'download {api.link} --size={api.size}')
            downByApi(api.link)
            count += 1
            print(f'{count}/{len(apis)}')

def getDirectoryNames():
    print("getDirectoryNames")
    DirectoryNames={}
    response = requests.get("https://mcfp.felk.cvut.cz/publicDatasets/").text
    pattern=re.compile('a href="(.*?)/"')
    names=pattern.findall(response)
    print(names)
    print("getDirectoryNames finished")
    return names

def getPcapNamesNew(directoryNames):
    # 限定大小
    print("getPcapNames")
    apis = []
    storage=[]
    count = 0
    for dName in directoryNames:
        tmp_apis = []
        print('dName : ' + dName)
        response = requests.get("https://mcfp.felk.cvut.cz/publicDatasets/" + dName).text

        soup = BeautifulSoup(response, 'html.parser')
        trs=soup.find_all('tr')

        for tr in trs:
            tds=tr.find_all('td')
            if len(tds)>1:
                # print(tds[1])
                td=tds[1]
                a=td.find('a')
                if a:
                    href=a['href']
                    if href.endswith('.pcap'):
                        href=a['href']
                        if href not in downloadedList:
                            pcapSize=tds[-2].text
                            link=Link("https://mcfp.felk.cvut.cz/publicDatasets/"+dName+"/"+href,pcapSize)
                            print(f'append {link}')
                            apis.append(link)
                            storage.append(link.dict())
        # time.sleep(2)
        count += 1
        # if count == 10:
        #     break
    with open(r"D:\lisa_v1\pcap\apis.txt", 'wb') as apisFile:
        apisFile.write(str(storage).encode(encoding='utf-8'))
    print("getPcapNames finished")
    return apis

def downloadByConfig(file):
    getdownloadedList("D:\lisa_v1\pcap")
    with open(file,'rb') as file:
        list_str=file.read().decode('utf-8')
        api_list=list_str.split(",")
        print('-------:',api_list)

        for api in api_list:
            print(api)
            # if (not api.size.endswith('G')) and api.link.split('/')[-1] not in downloadedList:
            #     print(api)
                # downByApi(api.link)

def getPcapNames(directoryNames):
    # 限定大小
    print("getPcapNames")
    apis=[]
    count=0
    for dName in directoryNames:
        tmp_apis=[]
        print('dName : '+dName)
        response = requests.get("https://mcfp.felk.cvut.cz/publicDatasets/"+dName).text
        pattern=re.compile('a href="(.*?.pcap)"')
        tmps=pattern.findall(response)
        for tmp in tmps:
            tmp_apis.append("https://mcfp.felk.cvut.cz/publicDatasets/"+dName+"/"+tmp)
        print(f'tmp_apis : {tmp_apis}')
        apis.extend(tmp_apis)
        # time.sleep(2)
        count+=1
        if count==10:
            break
    with open(r"D:\lisa_v1\pcap\apis.txt",'wb') as apisFile:
        apisFile.write(str(apis).encode(encoding='utf-8'))
    print("getPcapNames finished")
    return apis

def downByApi(api):
    pcapName=api.split('/')[-1]
    try:
        response=requests.get(api)
    except Exception as e:
        print(e)
    print("save to filesystem")
    with open(os.path.join("D:\lisa_v1\pcap",pcapName),"wb") as pcapfile:
        pcapfile.write(response.content)
    print('downByApi finished')

if __name__ == "__main__":
    # downloadByConfig(r'D:\lisa_v1\pcap\apis.txt')
    getApis()
    # getPcapNamesNew()
    # downByApi("CTU-Malware-Capture-Botnet-179-1","2016-06-22_win13.pcap")