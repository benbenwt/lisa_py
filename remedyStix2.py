import os
from stix2 import Bundle
# do not have objects
def remedy(directory):
    for root, sub_dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('json'):
                remedyAndSave(root,file)

def remedyAndSave(root,file):
    str=remedyResult(root,file)
    if not os.path.exists(os.path.join(root,"remedy")):
        os.mkdir(os.path.join(root,"remedy"))
    saveJsonFile(str,root,file)

def remedyResult(root,file):
    with open(os.path.join(root,file),'r',encoding='utf-8') as f:
        str=f.read()
        print(str)
        bundle_list=[]
        bundle_list.append(str)
        bundle = Bundle(bundle_list)
        bundle_str = bundle.serialize()
        return  bundle_str
def saveJsonFile(str,root,file):
    save_directory=os.path.join(root,"remedy",file)
    with open(save_directory, "wb") as save:
        save.write(str.encode())
    pass
if __name__=="__main__":
    remedy(r"D:\upload_data\1.31\1.31\cve\stix_data")