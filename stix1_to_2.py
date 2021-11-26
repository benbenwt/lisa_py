#coding:utf-8
import os
import re

from stix2 import (ThreatActor, Identity, Relationship, Bundle, Indicator, Malware)
from stix2 import parse
def create_attack_pattern(root):
    return
def create_compaign(root):
    return

def course_of_action(root):
    return

def create_grouping(root):
    return

def create_identity(xml):
    identity_result=[]
    identity_list=re.findall('<stixCommon:Identity>(.*?)</stixCommon:Identity>',xml,re.S)
    for identity in identity_list:
        name=''
        temp=re.findall('<stixCommon:Name>(.*?)</stixCommon:Name>',identity,re.S)
        if(len(temp)!=0):
            name=temp[0]
        identity_result.append(Identity(name=name))
    # print(identity_result)
    return identity_result

def create_indicator(xml):
    indicator_result=[]
    indicators = ''
    temp = re.findall('<stix:Indicators>(.*?)</stix:Indicators>', xml, re.S)
    if (len(temp) != 0):
        indicators=temp[0]
    indicator_list=re.findall('<stix:Indicator(.*?)</stix:Indicator>',indicators,re.S)
    for indicator in indicator_list:
        title =''
        temp=re.findall('<indicator:Title>(.*?)</indicator:Title>',indicator,re.S)
        if(len(temp)!=0):
           title=temp[0]
        description=title

        pattern_type='stix'
        temp=re.findall('<cyboxCommon:Type .*?">(.*?)</cyboxCommon:Type>',indicator,re.S)
        if(len(temp)!=0):
            hash_type=temp[0]
        #     pattern_type=temp[0]
        # else:
        #     temp = re.findall('<cybox:Properties.*?category="(.*?)">', indicator, re.S)
        #     if (len(temp) != 0):
        #         pattern_type = temp[0]
        pattern=''
        temp =re.findall('<cyboxCommon:Simple_Hash_Value>(.*?)</cyboxCommon:Simple_Hash_Value>', indicator, re.S)
        if (len(temp) != 0):
            # print(temp[0])
            if hash_type=='SHA256':
                pattern = "[file:hashes.'SHA-256'='" + temp[0] + "']"
            elif hash_type=='MD5':
                pattern ="[file:hashes.md5='"+temp[0]+"']"
            # print(pattern)
        else:
            temp = re.findall('<AddressObj:Address_Value>(.*?)</AddressObj:Address_Value>', indicator, re.S)
            if (len(temp) != 0):
                pattern ="[ipv4-addr:value ='"+temp[0]+"']"
            else:
                temp = re.findall('<URIObj:Value>(.*?)</URIObj:Value>', indicator, re.S)
                if (len(temp) != 0):
                    pattern = "[url:value ='"+temp[0]+"']"
                else:
                    temp = re.findall('<DomainNameObj:Value>(.*?)</DomainNameObj:Value>', indicator, re.S)
                    if (len(temp) != 0):
                        pattern = "[url:value ='" + temp[0] + "']"
                    else:
                        # print(pattern)
                        pattern_type=''
        if pattern=='':
            pattern_type=''
        r1=re.compile('\\\n')
        re.sub('\'','',pattern)
        re.sub(r1,'',pattern)
        re.sub('\\\=','=',pattern)
        # pattern="[user-account:value = '018a9569f559bfafbc433dc81caf3ec0']"
        # print(pattern)
        try:
            indicator_result.append(Indicator(name=title,description=description,pattern_type=pattern_type,pattern=pattern))
        except Exception:
            print(pattern)
    # print(indicator_result)
    return indicator_result

def create_infrastructure(root):
    return

def create_intrusion_set(root):
    return

def create_location(root):
    return

def create_malware(xml):
    malware_result=[]
    malware_list=re.findall('<ttp:Malware>(.*?)</ttp:Malware>',xml,re.S)
    for malware in malware_list:
        name=''
        temp=re.findall('<ttp:Name>(.*?)</ttp:Name>',malware,re.S)
        if(len(temp)!=0):
            malware=temp[0]
        is_family='false'
        malware_result.append(Malware(name=name,is_family=is_family))
    # print(malware_result)
    return malware_result

def create_malware_analysis(root):
    return

def create_note(root):
    return

def create_obserbed_data(root):
    return

def create_opinion(root):
    return

def create_report(root):
    return

def create_Relationships(root):
    return

def create_threat_actor(xml):
    threat_actor_result=[]
    threat_actors=''
    temp=re.findall("<stix:Threat_Actors>(.*?)</stix:Threat_Actors>",xml,re.S)
    if(len(temp)!=0):
        threat_actors=temp[0]
    threat_actor_list=re.findall('<stix:Threat_Actor(.*?)</stix:Threat_Actor>',threat_actors,re.S)
    for threat_actor in threat_actor_list:
        id=''+re.findall('id="(.*?)"',threat_actor)[0]
        id = id.replace('alienvault-otx:', '').replace('threatactor', 'threat-actor-')
        timestamp=''+re.findall('timestamp="(.*?)[0-9]{3}\+00:00"',threat_actor)[0]+'z'
        title=''+re.findall('<ta:Title>(.*?)</ta:Title>',threat_actor)[0]
        threat_actor_result.append(ThreatActor(id=id,created=timestamp,name=title))
    # print(threat_actor_result)
    return threat_actor_result

def create_tool(root):
    return

def create_vulnerability(root):
    return

def read_xml(filename):
    with open(filename,"r") as file:
        xml=file.read()
    return xml

def begin_convert(directory_name,save_directory):
    for root,sub_dirs,files in os.walk(directory_name):
        for file in files:
            # print(file)
            # os.renames(os.path.join(root,file),os.path.join(root,file+'.xml'))
            if file.endswith('xml')&os.path.isfile(os.path.join(root,file)):
                # print(file)
                try:
                    xml=read_xml(os.path.join(root,file))
                except Exception:
                    print(file+'is not a xml')
                    continue
                threat_actor_list=create_threat_actor(xml)
                identity_list=create_identity(xml)
                indicator_list=create_indicator(xml)
                malware_list=create_malware(xml)
                # str_head = '{"type": "bundle", "id": "bundle--8647f76b-53de-4a66-a14d-ea6c80f8b275", "objects": [ '
                # str_end = ']}'
                # bundle_str=str_head
                # for threat_actor in threat_actor_list:
                #     bundle_str=bundle_str+threat_actor.serialize()+','
                # for identity in identity_list:
                #     bundle_str = bundle_str + identity.serialize()+','
                # for indicator in indicator_list:
                #     bundle_str=bundle_str+indicator.serialize()+','
                # for malware in malware_list:
                #     bundle_str=bundle_str+malware.serialize()+','
                # bundle_str=bundle_str[:-1]+str_end
                bundle_list=[]
                for threat_actor in threat_actor_list:
                    bundle_list.append(threat_actor)
                for identity in identity_list:
                    bundle_list.append(identity)
                for indicator in indicator_list:
                    bundle_list.append(indicator)
                for malware in malware_list:
                    bundle_list.append(malware)
                bundle=Bundle(objects=bundle_list)
                file=file.replace('xml','json')
                # with open(os.path.join(save_directory,file),"wb") as save:
                #     save.write(bundle.serialize().encode())
                # bundle=parse(bundle_str)
                # print(bundle)

if __name__=='__main__':
    str ='{"type": "bundle", "id": "bundle--8647f76b-53de-4a66-a14d-ea6c80f8b275", "objects": [ '
    str_end = ']}'
    xml=read_xml('/555.xml')
    threat_actor_list=create_threat_actor(xml)
    identity_list=create_identity(xml)
    indicator_list=create_indicator(xml)
    malware_list=create_malware(xml)
    indicator=indicator_list[0]
    indicator_str=indicator.serialize()
    print(parse(str+indicator_str+str_end))