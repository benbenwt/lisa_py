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
    response_str=json.dumps(response,sort_keys=True,indent=2,separators=(',',':'))
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

if __name__=="__main__":
    submit_diretory=r'D:\qbitdownload\VirusShare_ELF_20190212'
    report_directory='/home/yoki/PycharmProjects/lisa/report'

    # task_id=virus_pcap(submitfile_api,"/home/yoki/PycharmProjects/lisa/testbin",'file')
    # time.sleep(40)
    # get_report(getreport_api,task_id=task_id)

    # task_id = virus_pcap(submitpcap_api, "/home/yoki/PycharmProjects/lisa/2.pcap", 'pcap')
    # time.sleep(60)
    # get_report(getreport_api, task_id=task_id)

    id_list=get_id_list(submit_diretory,lisa_path="http://172.18.65.185:4242")
    print('upload finish....')
    time.sleep(120)
    # get_report_list(getreport_api,id_list=id_list,path=report_directory)