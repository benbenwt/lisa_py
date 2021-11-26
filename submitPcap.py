import os

import requests

if __name__=='__main__':
    root_dir=r'D:\upload_data\manageddata\pcapTraffic2014-17'
    for file in os.listdir(root_dir):
        pcap_file=os.path.join(root_dir,file)
        print(pcap_file)
        data = {'pcap': open(pcap_file, 'rb'),
                }
        response = requests.post(r'http://172.18.65.186:8344/pcapSubmit', files=data).text
        print(response)
    # request.post()