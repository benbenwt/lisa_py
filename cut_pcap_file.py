# encoding:gbk
import os
import subprocess


def scanFiles(directory):
    print('start scanFiles')
    for root, sub_dirs, files in os.walk(directory):
        for file in files:
            size=os.path.getsize(os.path.join(root,file))
            if file.endswith('pcap') and size/1024/1024>=40:
                cut_pcap(root,file,5120)
def cut_pcap(root,file,cutSize):
    srcPath=os.path.join(root,file)
    print(f"srcPath: {srcPath}-- cutSize : {cutSize}")
    dstPath=os.path.join(r'D:\upload_data\es_import2\new_pcap_cut',file)
    # dstPath=os.path.join(root,file.replace(".pcap",""),file)
    print(f"dstPath : {dstPath}")
    os.system(f"C:\\Program Files\\Wireshark\\editcap  -c {cutSize} {srcPath} {dstPath} ")

    os.chdir("C:\\Program Files\\Wireshark")
    p = subprocess.Popen(['cmd', '/c', 'dir'],
                         stdout=subprocess.PIPE,
                         universal_newlines=True)

    p = subprocess.Popen(['cmd', '/c', "editcap", "-c", "20480",
                          f"{srcPath}",
                          f"{dstPath}"],
                         stdout=subprocess.PIPE,
                         universal_newlines=True)
    out = p.communicate()
    print(out)
if __name__=="__main__":
    scanFiles(r"D:\lisa_v1\pcap")
