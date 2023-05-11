#！coding=utf-8
import requests
import time
import os
import re
import json
submitfile_api = '/api/tasks/create/file'
getreport_api = '/api/report/'
submitpcap_api = '/api/tasks/create/pcap'
id_filename={}

def submit(api,file,param):
    data={param:open(file,'rb'),
          'exec_time':'60'
          }

    response=requests.post(api,files=data).json()


    print(file,"<-->",response['task_id'])
    # id_filename[response['task_id']]=file
    return response['task_id']



def get_report(api,task_id):
    response=requests.get(api+task_id).json()
    f=open('/home/yoki/PycharmProjects/lisa/1.json','wb')
    response_str=json.dumps(response,sort_keys=True,separators=(',',':'))
    f.write(response_str.encode())
    f.close()

def get_report_list(api,id_list,path):
    for id in id_list:
        response = requests.get(api+getreport_api + id).json()
        try:
            f=open(path+'/'+id+'.json','wb')
            # filename=id_filename[id]
            response_str =json.dumps(response,sort_keys=True,indent=2,separators=(',',':'))
            f.write(response_str.encode())
            f.close()
        except Exception as e:
            print('open file failed')
            print(e)
    print('report_list finish!')

def get_id_list(directory,lisa_path):
    count=0
    fileList=[]
    pcapList=[]
    id_list=[]
    for root,sub_dirs,files in os.walk(directory):
        for file in files:
            if file.endswith('pcap'):
                pcapList.append(os.path.join(root,file))
            elif file.endswith('json'):
                continue;
            else:
                fileList.append(os.path.join(root,file))
    # print('fileList ', fileList)
    # print('pcapList ', pcapList)
    fileLen= len(fileList)
    for file in fileList:
        try:
            id=submit(lisa_path+submitfile_api,file,'file')
            count += 1
            print(f'{count}/{fileLen}')
        except Exception as e:
            print(file + ' file failed')
            print(e)
            continue
        id_list.append(id)
    for pcap in pcapList:
        try:
            id=submit(lisa_path+submitpcap_api,pcap,'pcap')
        except Exception:
            print(file + 'pcap failed')
            continue
        id_list.append(id)
    print('id_list:',id_list)
    return id_list

from hashlib import md5

def submit_pdf(api,file,param):
    name=file.split("\\")[-1].encode("utf-8")
    print(name)

    id=md5(name).hexdigest()
    files={
        param:open(file,'rb')
          }
    data={
        'id': id,
        "time": "",
        "url": ""
    }
    response=requests.post(url=api,files=files,data=data).json()


    print(file.encode("utf-8"),"<-->",response)
    # id_filename[response['task_id']]=file
    return

def main_malware():
    # D:\迅雷下载\temp
    submit_diretory = r'D:\japan_samples\japan_samples\new_sample1\part4'
    report_directory = '/home/yoki/PycharmProjects/lisa/report'

    # task_id=virus_pcap(submitfile_api,"/home/yoki/PycharmProjects/lisa/testbin",'file')
    # time.sleep(40)
    # get_report(getreport_api,task_id=task_id)

    # task_id = virus_pcap(submitpcap_api, "/home/yoki/PycharmProjects/lisa/2.pcap", 'pcap')
    # time.sleep(60)
    # get_report(getreport_api, task_id=task_id)

    id_list = get_id_list(submit_diretory, lisa_path="http://172.18.65.185:4242")
    print('upload finish....')
    time.sleep(120)
    # get_report_list(getreport_api,id_list=id_list,path=report_directory)

def submit_pdf_directory(directory,lisa_path):
    count=0
    fileList=[]
    id_list=[]
    for root,sub_dirs,files in os.walk(directory):
        for file in files:
            fileList.append(os.path.join(root,file))

    fileLen= len(fileList)
    for file in fileList:
        try:
            submit_pdf("http://172.18.65.186:8344/cti_api", file, "file")
            count += 1
            print(f'{count}/{fileLen}')
        except Exception as e:
            print(file.encode("utf-8") + ' pdf failed'.encode("utf-8"))
            print(e)
            continue
    return id_list

def main_pdf():
    id_list = submit_pdf_directory(r"C:\Users\guo\Documents\WeChat Files\wxid_seks98w3chxb22\FileStorage\File\2023-02\威胁事件20230210", lisa_path="http://172.18.65.185:4242")
    print('upload finish....')
    time.sleep(120)
    # get_report_list(getreport_api,id_list=id_list,path=report_directory)

if __name__=="__main__":
    main_malware()
    # main_pdf()