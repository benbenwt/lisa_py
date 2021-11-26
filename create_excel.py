import os
import re
import csv
import time

import requests
headers = {
        ':authority': 's.threatbook.cn',
        ':method': 'GET',
        ':path': '/api/v3/webpage/multi_engines/d50466c6967441b7759ac81d4528834921517b4381792c09f1386d7071be7988',
        ':scheme': 'https',
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'cookie': 'gr_user_id=8c864d9e-bfce-49be-87d3-0ebfe714472d; grwng_uid=b5c89241-d46a-495a-b4b9-ef7613746a3f; a341bf1034872a74_gr_session_id=ea0205f3-d608-4dcc-88f7-4b86baef9460; a341bf1034872a74_gr_session_id_ea0205f3-d608-4dcc-88f7-4b86baef9460=true',
        'referer': 'https://s.threatbook.cn/report/file/d50466c6967441b7759ac81d4528834921517b4381792c09f1386d7071be7988/?sign=history&env=win7_sp1_enx64_office2013',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36'
    }

def create_excel(row_list):
    headers=['sample','type']
    with open("data20210316.csv",'a',encoding='utf-8',newline='') as f:
        f_csv=csv.writer(f)
        f_csv.writerow(headers)
        f_csv.writerows(row_list)
    return

#get type from xml
def begin(directory_name):
    i=0
    row_list=[]
    for root,sub_dirs,files in os.walk(directory_name):
        for file in files:
            i=i+1
            if file.endswith('xml')&os.path.isfile(os.path.join(root,file)):
                try:
                    with open(os.path.join(root,file),'r') as f:
                        xml=f.read()
                except Exception:
                    print(file+'is not a xml')
                    continue
                temp = re.findall(" <stix:Title>(.*?)</stix:Title>", xml, re.S)
                if len(temp)>0:
                    title=temp[0]
                # print(title)

                row=[]
                file_new=re.sub('.xml','.json',file)
                row.append(file_new)
                row.append(title)

                type='IoT malware'
                c1=re.compile(r'[0-9]{1,}(.*?)\(S3\#\)',re.X)
                temp=re.findall(c1,title)
                if len(temp)>0:
                    type=temp[0]
                sample_list=['DDos','Mirai','EchoBot','Botnet','Hajime','LiquorBot','DDoS','MIrai','BrickerBot','FBot','IOT']
                for list_ele in sample_list:
                    c1=re.compile(list_ele,re.I)
                    temp = re.findall(c1,title)
                    if len(temp) > 0:
                        type =list_ele
                        break
                row.append(type)
                row_list.append(row)
    create_excel(row_list);
    print('i=',i)
    return

def rename_directory(row_list):
    for root,sub_dirs,files in os.walk('/home/yoki/sdb/ThreatIntelligence/stix2/virusELS2019stix2'):
        for file in files:
            os.rename(os.path.join(root,file),os.path.join(root,file))
    return

#get type
def get_type(hash):
    time.sleep(2)
    url = 'https://api.threatbook.cn/v3/file/report'
    params = {
        'apikey': '41ae4fe9516f41ba86e11a796581e4bb6d1ae89830e84edcb213b4295f081fb3',
        'sandbox_type': 'win7_sp1_enx64_office2013',
        'md5': hash
    }
    response = requests.get(url, params=params)
    request = dict(response.json())
    if "data" in request:
        data = request["data"]
        summary = data["summary"]
        tag = summary["tag"]
        if "x" in tag:
            x = tag["x"]
            return(x)
        else: return False
    else:return False

# set malware by querying lisa again
def lisa_csv1():
    response=requests.get('http://localhost:4242/api/tasks/finished').json()
    row_list=[]
    filename_list=[]
    # row1_list=[]
    for block in response:
        if block['result']['filename'] in filename_list:
            continue
        task_id=block['task_id']
        filename=block['result']['filename']
        filename_list.append(filename)
        # print(task_id,filename)
        row=[]

        filename=re.sub('VirusShare_','',filename)
        row.append(filename+'.json')
        row.append('malware')
        row_list.append(row)
    create_excel(row_list)
    return

#set malware using directory
def lisa_csv(directory):
    row_list=[]
    for root, sub_dirs, files in os.walk(directory):
        for file in files:
            row=[]
            row.append(file)
            row.append('malware')
            row_list.append(row)
    create_excel(row_list)
    return

#get type
def lisa_csv(directory):
    row_list=[]
    headers=['sample','type']
    for root,sub_dirs,files in os.walk(directory):
        for file in files:
            hash=re.sub('.json','',file)
            type=get_type(hash)
            row=[]
            row.append(file)
            row.append(type)
            print(file)
            row_list.append(row)
    # for i in range(0,2):
    #     for r in row_list:
    #         if r[1]==False:
    #             hash=re.sub('.json','',r[0])
    #             type=get_type(hash)
    #             r[1]=type
    #             print(hash,' ',type)
    create_excel(row_list)

if __name__=='__main__':
    # begin('/home/yoki/sdb/ThreatIntelligence/source/otx_xml');
    # begin('/home/yoki/sdb/ThreatIntelligence/source/stix_collection');
    # lisa_csv('/home/yoki/sdb/ThreatIntelligence/stix2/ELF2019-5-SHA256')
    # lisa_csv('/home/yoki/sdb/ThreatIntelligence/stix2/ELF2018-6-SHA256')
    lisa_csv('/home/yoki/sdb/ThreatIntelligence/stix2/VirusShare_ELF_20140617_part1')

