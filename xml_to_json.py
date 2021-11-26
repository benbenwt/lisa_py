import json
import os
import re

import xmltodict


def xml2_json(path1,path2):
    for root,sub_dirs,files in os.walk(path1):
        for file in files:
            with open(os.path.join(root,file),'r') as f:
                try:
                    xml = f.read()
                    json_dict = xmltodict.parse(xml)
                except Exception:
                    print(file+' is not a formate xml')
                    continue
                json_str = json.dumps(json_dict)
                json_str = re.sub(',', ',\n', json_str)
                file=file.replace('xml', 'json')
                with open(os.path.join(path2, file), 'wb') as result:
                    result.write(json_str.encode())