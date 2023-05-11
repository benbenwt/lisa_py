import json
import re
import os

def json_formate(path1=r'D:\threat_intelligence\Alien\Alien\stix_data',path2=r'D:\threat_intelligence\Alien\Alien\noindentStix_data'):
        for root,sub_dirs,files in os.walk(path1):
            for file in files:
                path=os.path.join(root,file)
                with open(path,'rb') as file2:
                    json_dict=json.load(file2)
                    # json_str=json.dumps(json_dict, sort_keys=True, indent=4, separators=(',', ': '))
                    json_str = json.dumps(json_dict)
                    save_path=os.path.join(path2,file)
                    with open(save_path,'w') as ff:
                        ff.write(json_str)


if __name__=='__main__':
    json_formate()
