import pymysql

db = pymysql.connect(host='172.18.65.185', port=3306, user='root', password='root', database='platform',charset='utf8')
cursor = db.cursor()
last_time =read+time
time = T.strftime("%Y-%m-%d %H:%M:%S", T.localtime())
sql = f"select * from cve where s_time > '2021-02-02'"
cursor.execute(sql)
res = cursor.fetchall()
print(res[0])
print(res[0][1])
results = [{'id': r[1], 'atime': r[5],"title": r[4],"cve":r[3],"url":r[-1]} for r in res]
print(results[0])
new_results = [r for r in results if r['atime'] != '' and r['atime']!=None and r['atime'] > last_time]


