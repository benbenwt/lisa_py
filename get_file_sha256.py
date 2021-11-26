import hashlib
import os
import re
import csv
import time
import shutil

if __name__=='__main__':
    for root, sub_dirs, files in os.walk("/home/yoki/sdb/ThreatIntelligence/source/VirusShare_ELF_20140617_part1"):
        for file in files:
            with open(os.path.join(root,file),'rb') as f:
                 data =f.read()
                 if data:
                    # get file`s sha256 value
                    sha256_value=hashlib.md5(data).hexdigest()
                    print(sha256_value)
                    #copy file to another directory and rename by sha256
                    shutil.copy(os.path.join(root,file),os.path.join("/home/yoki/sdb/ThreatIntelligence/source/VirusShare_ELF_20140617_part1_new",sha256_value));
                 else:
                    continue;


