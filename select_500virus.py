import os
import re
import csv
import time
import shutil
import hashlib

def select_by_sha256(stix2_dirctory,src_root,dst_root):
    for root, sub_dirs, files in os.walk(stix2_dirctory):
        for file in files:
            sha256_value = re.sub(".json", "", file);
            srcfile = src_root + sha256_value;
            dstfile = dst_root + sha256_value;
            print(srcfile);
            print(dstfile);
            shutil.copy(srcfile, dstfile);

def select_by_md5():
    for root, sub_dirs, files in os.walk("/home/yoki/sdb/ThreatIntelligence/stix2/500_virus_md5"):
        for file in files:
            name=re.sub(".json","",file);
            srcfile="/home/yoki/sdb/ThreatIntelligence/source/japan_samples/malware/random4000_iot_mal_20161002-20171002/"+name;
            dstfile="/home/yoki/sdb/ThreatIntelligence/source/500virus_md5/"+name;
            print(srcfile);
            print(dstfile);
            try:
                shutil.copy(srcfile,dstfile);
            except Exception:
                print("not found !")

if __name__=='__main__':
    # select_by_sha256("/home/yoki/sdb/ThreatIntelligence/stix2/500_virus_SA256","/home/yoki/sdb/ThreatIntelligence/source/japan_malware_sha256/","/home/yoki/sdb/ThreatIntelligence/source/500virus_sha256/")
    # select_by_sha256("/home/yoki/sdb/ThreatIntelligence/stix2/ELF2018-6-SHA256/",
    #                  "/home/yoki/sdb/ThreatIntelligence/source/ELF2018-6/",
    #                  "/home/yoki/sdb/ThreatIntelligence/source/ELF2018-6_SELECT/")
    select_by_sha256("/home/yoki/sdb/ThreatIntelligence/stix2/ELF2019-5-SHA256/",
                     "/home/yoki/sdb/ThreatIntelligence/source/ELF2019-5/",
                     "/home/yoki/sdb/ThreatIntelligence/source/ELF2019-5_SELECT/")