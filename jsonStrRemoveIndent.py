# coding=utf-8
import json
import os

if __name__ == '__main__':
    directory=r'C:\Users\guo\Desktop\spring漏洞\temp'
    save=os.path.join(directory, "withoutIndent")
    for path in os.listdir(directory):
        if path.endswith(".json"):
            fullPath=os.path.join(directory,path)
            print(fullPath)
            with open(fullPath,encoding='utf-8') as fp:
                str=fp.read()
                print(str)
            with open(os.path.join(save,path),'w') as f1:
                ss=str.replace("\r","").replace("\n","").replace(" ","")
                print(ss)
                object=json.loads(ss)
                json.dump(object,f1)
