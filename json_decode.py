import json

import urllib3

url = f"http://172.18.65.186:8345/cvelist/1082"
http = urllib3.PoolManager()
r = http.request(
    "GET",
    url,
    headers={'Accept': '*/*',
             'Accept-Encoding': 'gzip,deflate,br',
             'Accept-Language': 'zh-CN',
             'User-Agent': 'PostmanRunt/7.26.8',
             }
)
print(r.data)
res = json.loads(r.data)["cves"]
print(res)