import json
import re
import os

def json_formate(path1='/home/yoki/PycharmProjects/lisa/need_format _json',path2='/home/yoki/PycharmProjects/lisa/json_formate_result/'):
        for root,sub_dirs,files in os.walk(path1):
            for file in files:
                path=os.path.join(root,file)
                with open(path,'r') as file2:
                    json_dict=json.load(file2)
                    json_str=json.dumps(json_dict, sort_keys=True, indent=4, separators=(',', ': '))
                    # print(json_str)
                    save_path=os.path.join(path2,file)
                    with open(save_path,'wb') as ff:
                        ff.write(json_str.encode())


if __name__=='__main__':
    json_formate()
