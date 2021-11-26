import os
import shutil


def select_json_file(src_root,dst_root):
    for root,sub_dirs,files in os.walk(src_root):
        for file in files:
            if file.endswith('json'):
            #copy
                dstfile=os.path.join(dst_root,file)
                print(f"{file}----->{dstfile}")
                shutil.copy(os.path.join(root,file), dstfile);

if __name__=="__main__":
    select_json_file(r"D:\upload_data\20210427\malware\malware\malware",r"D:\upload_data\es_import2\test")
