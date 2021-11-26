import os

import stix2elevator
from stix2elevator import elevate
from stix2elevator.options import initialize_options
import stix2validator
from stix2validator import print_results


def convert_directory(path1,path2):
    initialize_options()
    for root,dirs,files in os.walk(path1):
        for file in files:
            if file.endswith('xml'):
                print(file)
                results = elevate(os.path.join(root,file))
                file=file.replace('xml','json')
                with open(os.path.join(path2,file), 'wb') as file:
                    file.write(results.encode())
                print('-----------------------------fen---------------------------------------------------', file)

def validate_directory(path):
    result_list=[]
    initialize_options()
    for root,dirs,files in os.walk(path):
        for file in files:
            if file.endswith('json'):
                results=stix2validator.validate_file(os.path.join(root,file))
                print(file,results.is_valid)
                print_results(results)
                result_list.append("The result of "+file+" is "+str(results.is_valid))
    return result_list

def convert():
    initialize_options()
    try:
        results = elevate("/home/yoki/sdb/PycharmProjects/lisa/xml/st.xml")
    except Exception:
        print('error')
        return
    print(results)

if __name__=="__main__":
    # convert_directory('/home/yoki/sdb/stix_collection','/home/yoki/sdb/PycharmProjects/lisa/stix2')
    validate_directory('/home/yoki/sdb/PycharmProjects/lisa/stix2')
