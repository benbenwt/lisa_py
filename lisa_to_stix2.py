import os
from datetime import datetime, timedelta


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

def get_content(filename):
    with open(filename,'r') as f:
        content=f.read()
    # print(content)
    content_dict=json.loads(content)
    print(type(content_dict))
    return content_dict
def create_threat_actor(content):
    return
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
    indicator=Indicator(name=name,description=description,pattern_type=pattern_type,pattern=pattern,indicator_types=indicator_types)
    indicator_list.append(indicator)

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

    name = "Size of malware object"
    description = "Malware size."
    size=content['static_analysis']['binary_info']['size']
    size_pattern="[file:size="+str(size)+"]"
    indicator3 = Indicator(name=name, description=description, pattern_type=pattern_type, pattern=size_pattern,
                           indicator_types=indicator_types)
    indicator_list.append(indicator3)

    return indicator_list


def create_malware_analysis(content):
    start_time=content['analysis_start_time'];
    start_time=start_time+':00Z'
    softwares=create_software(content);
    object_list = []
    if len(sco_list)>0:
        malware_analysis=MalwareAnalysis(type='malware-analysis',product='binwalk',version='2.2.0',host_vm_ref=host_software_ref,operating_system_ref =software_ref,analysis_started=start_time,analysis_sco_refs=sco_list)
        object_list.append(malware_analysis)
    for software in softwares:
        object_list.append(software)
    return object_list

def create_software(content):

    value = get(get(get(content, 'static_analysis'), 'binary_info'), 'arch')
    if value!=-1:
        operation_system="linux_"+value;
    software=Software(type='software',name=operation_system)
    global software_ref
    software_ref=software['id']

    host_software = Software(type='software', name='qemu',version='2.5.0')
    global host_software_ref
    host_software_ref = software['id']

    softwares=[];
    softwares.append(software)
    softwares.append(host_software);
    return softwares

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

    endianess=content['static_analysis']['binary_info']['endianess']
    descriptions='The malware ofen run on '+ports+' ports.The md5 value is '+md5+".endianess-"+endianess+"-"
    architecture=[]
    value =get(get(get(content,'static_analysis'),'binary_info'),'arch')

    if (value != -1):
        architecture.append(value)

    language =[]
    value =get(get(get(content,'static_analysis'),'binary_info'),'language')

    if (value != -1):
        language.append(value)

    malware=Malware(name=sha256,aliases=file_name,is_family='false',description=descriptions,architecture_execution_envs=architecture,implementation_languages=language)
    global target_ref
    target_ref=malware['id']
    return malware

def create_ipv4(content):
    ref_list = []
    ipv4_object_list=[]
    value = get(get(content, 'network_analysis'), 'endpoints')
    points_l=''
    if value!=-1:
        points_l=value
    for points in points_l:
        ip = get(points, 'ip')
        if ip != -1:
            ipv4_object = IPv4Address(type='ipv4-addr',value=ip)
            ipv4_object_list.append(ipv4_object)
            ref_list.append(ipv4_object['id'])
    return (ipv4_object_list,ref_list)

def create_processes(content):
    processes=''
    value = get(get(content, 'dynamic_analysis'), 'processes')
    if value!=-1:
        processes=value
    process_list = []
    process_ref=[]

    for process in processes:
        process_object = Process(pid=process['pid'],command_line=process['pid'])
        process_list.append(process_object)
        process_ref.append(process_object['id'])
        # pid_id[process['pid']] = process_object['id']

    syscalls=[]
    value = get(get(content, 'dynamic_analysis'), 'syscalls')
    if value!=-1:
        syscalls=value
    for syscall in syscalls:
        argument = {'argument':syscall['arguments']}
        process_object=Process(command_line=syscall['name'],environment_variables=argument)
        process_list.append(process_object)
        process_ref.append(process_object['id'])

    return  (process_list,process_ref)

def create_file(content):
    files = []
    value = get(get(content,'dynamic_analysis'),'open_files')
    if value!=-1:
        files=value
    file_list=[]
    file_ref=[]
    for file in files:
        file_obj=File(name=file)
        file_list.append(file_obj)
        file_ref.append(file_obj['id'])
    return (file_list,file_ref)

def create_observed_data(content):
    now_time=datetime.now()
    utc_time=now_time-timedelta(hours=8)
    utc_time=utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(utc_time)

    (ipv4_object_list,ip_ref)=create_ipv4(content)
    (processes,process_ref)=create_processes(content)
    (files,file_ref)=create_file(content)

    ref_list = []
    for id in ip_ref:
        ref_list.append(id)
    for id in process_ref:
       ref_list.append(id)
    for id in file_ref:
        ref_list.append(id)

    global sco_list
    sco_list=ref_list
    object_list = []
    if len(ref_list)>0:
        observed_data = ObservedData(first_observed=utc_time, last_observed=utc_time,number_observed=1,object_refs=ref_list)
        object_list.append(observed_data)


    for ipv4 in ipv4_object_list:
        object_list.append(ipv4)
    for process in processes:
        object_list.append(process)
    for file in files:
        object_list.append(file)
    return object_list

def convert_to_stix2(directory_name,save_directory):
    for root,sub_dirs,files in os.walk(directory_name):
        for file in files:
            if file.endswith('json')&os.path.isfile(os.path.join(root,file)):
                print(file)
                content=get_content(os.path.join(root,file))
                if 'error' in content.keys():
                    continue
                malware=create_malware(content)
                indicator_list = create_indicator(content)
                relation_list=create_relationship(indicator_list,malware)
                observed_data_list=create_observed_data(content)
                malware_analysis_list=create_malware_analysis(content)

                md5=content['md5']
                print(md5)

                bundle_list=[]
                bundle_list.append(malware);
                for indicator in indicator_list:
                    bundle_list.append(indicator);
                for relation in relation_list:
                    bundle_list.append(relation);
                for ob in observed_data_list:
                    bundle_list.append(ob)

                for ob in malware_analysis_list:
                    bundle_list.append(ob)

                bundle= Bundle(bundle_list)
                bundle_str = bundle.serialize()
                with open(os.path.join(save_directory,md5+'.json'),"wb") as save:
                    save.write(bundle_str.encode())
                # print(bundle)

if __name__=='__main__':
    convert_to_stix2(r'/home/yoki/sdb/PycharmProjects/lisa/report',r'/home/yoki/sdb/PycharmProjects/lisa/stix2')