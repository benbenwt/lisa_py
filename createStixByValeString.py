import os
import time
from sys import argv

import timer
from stix2 import (File,Software,MalwareAnalysis,ThreatActor, Malware, parse, Indicator, Bundle, Relationship, ObservedData, IPv4Address, Process)

import json

source_ref=''
target_ref=''
software_ref=''
host_software_ref=''
sco_list=''
def get(input_d,key):
    if(type(input_d)==int):
        return -1
    return input_d.get(key,-1)


def create_relationship(indicator_list,malware):
    relation_list=[]
    for indicator in indicator_list:
        relation=Relationship(source_ref=indicator, target_ref=malware['id'], relationship_type='indicates')
        relation_list.append(relation)
    return relation_list

def create_indicator(content):
    name="SHA256 for malware object"
    description="This hash indicates the present of Malware."
    pattern=''
    # temp=re.findall('"sha256":"(.*?)"',content)
    # if len(temp)!=0:
    value= get(content,'sha256')
    if(value!=-1):
        pattern = "[file:hashes.'SHA-256'='" + value + "']"
    else:
        return None
    indicator_types =["malicious-activity"]
    pattern_type='stix'
    indicator_list=[]
    try:
        indicator=Indicator(name=name,description=description,pattern_type=pattern_type,pattern=pattern,indicator_types=indicator_types)
        indicator_list.append(indicator)
    except:
        return  []
    name = "MD5 for malware object"
    description = "This hash indicates the present of Malware."
    md5=content['md5']
    md5_pattern = "[file:hashes.'MD5'='" + md5 + "']"
    indicator1=Indicator(name=name,description=description,pattern_type=pattern_type,pattern=md5_pattern,indicator_types=indicator_types)
    indicator_list.append(indicator1)

    name = "SHA1 for malware object"
    description = "This hash indicates the present of Malware."
    sha1=content['sha1']
    sha1_pattern = "[file:hashes.'SHA-1'='" + sha1 + "']"
    indicator2=Indicator(name=name,description=description,pattern_type=pattern_type,pattern=sha1_pattern,indicator_types=indicator_types)
    indicator_list.append(indicator2)



    return indicator_list


def create_malware_analysis(content):
    start_time=time.strftime("yyyy-MM-dd",time.localtime(time.time())).__str__();
    start_time=start_time+':00Z'

    object_list = []
    if len(sco_list)>0:
        malware_analysis=MalwareAnalysis(type='malware-analysis',product='binwalk',version='2.2.0',host_vm_ref=host_software_ref,operating_system_ref =software_ref,analysis_started=start_time,analysis_sco_refs=sco_list)
        object_list.append(malware_analysis)
    return object_list



def create_malware(content):
    sha256=''
    value =get(content,'sha256')
    if (value != -1):
        sha256 = value
    md5=''
    value =get(content,'md5')
    if (value != -1):
        md5 = value
    file_name=''
    value = get(content,'file_name')
    if (value != -1):
        file_name = value
    ports=''
    points_l=''
    value =get(get(content,'network_analysis'),'endpoints')
    if(value!=-1):
        points_l=value

    for points in points_l:
        ports=ports+get(points,'ports')[0]+','


    # descriptions='The malware ofen run on '+ports+' ports.The md5 value is '+md5+".endianess-"+endianess+"-"
    architecture=[]
    # value =get(get(get(content,'static_analysis'),'binary_info'),'arch')
    value =get(content,'arch')
    if (value != -1):
        architecture.append(value)

    language =[]
    value =get(get(get(content,'static_analysis'),'binary_info'),'language')

    if (value != -1):
        language.append(value)

    malware=Malware(name=sha256,aliases=md5,is_family='false',architecture_execution_envs=architecture,implementation_languages=language)
    global target_ref
    target_ref=malware['id']
    return malware








def createStixByValueString(str):
    content=json.loads(str.__str__())
    malware = create_malware(content)
    indicator_list = create_indicator(content)
    relation_list = create_relationship(indicator_list, malware)
    malware_analysis_list = create_malware_analysis(content)

    md5 = content['md5']
    # print(md5)

    bundle_list = []
    bundle_list.append(malware);
    for indicator in indicator_list:
        bundle_list.append(indicator);
    for relation in relation_list:
        bundle_list.append(relation);

    # for ob in malware_analysis_list:
    #     bundle_list.append(ob)

    bundle = Bundle(bundle_list)
    bundle_str = bundle.serialize()

    print(bundle_str)
    return bundle_str

if __name__=='__main__':
    # createStixByValueString(r'{"sha1":"77eb651fd136a62d01d045a491dbfcbe77616797","sha256":"02c25e14918819dc8bdcd094dca39e46a9db089f3144c915faa0f712992ae37b","md5":"7b2d6c6fe5b3cc92c0b7bafa016ca54e","arch":"aaa"}')
    # print(argv[1])
    createStixByValueString(argv[1])