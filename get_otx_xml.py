import os

import requests
import re

headers={
     'Accept':'application/json, text/plain, */*',
     'Accept-Encoding':'gzip, deflate, br',
    'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8',
    'Authorization':'cee4ffdc9993b8808ae16f43325bd578ebbf0464',
    'Connection':'keep-alive',
    'Cookie':'_biz_uid=95d71b192fe1495fe9090cb34b30521c; _ga=GA1.2.1653348208.1601967727; _biz_flagsA=%7B%22Version%22%3A1%2C%22XDomain%22%3A%221%22%2C%22ViewThrough%22%3A%221%22%2C%22Frm%22%3A%221%22%7D; _gid=GA1.2.1265785171.1602225100; _biz_nA=60; amplitude_id_d684c2e36ffb45132cc2c08db2c16abfalienvault.com=eyJkZXZpY2VJZCI6ImNhZTcxMTEwLWZiYWItNDU0Yi1hYzk1LWI2ZGFiZWQ1NTQwOFIiLCJ1c2VySWQiOiJ1bmRlZmluZWQiLCJvcHRPdXQiOmZhbHNlLCJzZXNzaW9uSWQiOjE2MDIyMjUwOTk2MjIsImxhc3RFdmVudFRpbWUiOjE2MDIyMjg2MTE0MDEsImV2ZW50SWQiOjExOSwiaWRlbnRpZnlJZCI6MCwic2VxdWVuY2VOdW1iZXIiOjExOX0=; _biz_pendingA=%5B%5D; authkeys="auth_token:cee4ffdc9993b8808ae16f43325bd578ebbf0464:1kQnIz:H9ssAUuk6KSQShtYHoBpZY3qkD4"',
    'Host':'otx.alienvault.com',
    'Referer':'https://otx.alienvault.com/',
    'Sec - Fetch - Dest':'empty',
    'Sec - Fetch - Mode':'cors',
    'Sec - Fetch - Site':'same - origin',
    'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
    'X-OTX-USM-USER':'0'
    }

def get_page(page):
    url= 'https://otx.alienvault.com/otxapi/pulses/?limit=50&page=' + page + '&sort=-modified&q=mirai'
    # params={
    #     'limit':'20',
    #     'page':'7',
    #     'sort':'modified',
    #     'q':'mirai'
    # }
    response=requests.get(url,headers=headers).text;
    # print(response)
    id_list=re.findall('"id": "([\w]{24})"',response)
    print(id_list,len(id_list))
    return  id_list

def get_xml(id_list):
    token_list=[]
    for id in id_list:
        url='https://otx.alienvault.com/otxapi/pulses/'+id+'/generate_temp_token/?format=stix'
        response=requests.get(url,headers=headers).json()
        token=response['token']
        print(token)
        get_xml_url = 'https://otx.alienvault.com/otxapi/pulses/'+id+'/export/?token='+token+'&format=stix'
        response=requests.get(get_xml_url).text
        # print(response)
        with open(os.path.join('/home/yoki/sdb/ThreatIntelligence/source/otx_xml',str(id)+'.xml'),'wb') as f:
            f.write(response.encode())
def start():
    for i in range(10,11):
        print('page='+str(i))
        id_list=get_page(str(i))
        get_xml(id_list)
if __name__=='__main__':
    # pulse_id='1'
    # page='3'
    # get_id_url='https://otx.alienvault.com/otxapi/pulses/?limit=100&page='+page+'&sort=-modified&q=mirai'
    # get_token_url='https://otx.alienvault.com/otxapi/pulses/'+pulse_id+'/generate_temp_token/?format=stix'
    # token='1'
    # get_xml_url='https://otx.alienvault.com/otxapi/pulses/'+pulse_id+'/export/?token='+token+'+&format=stix'
    start()