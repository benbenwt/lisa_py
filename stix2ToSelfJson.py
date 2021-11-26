import json

templateSelfJson={"iocs":{},"cves":[],"attackers":[],"malwares":[],"locations":[],"types":[],"pattern":[]}
templateGraph={"data":[],"links":[],"iocs":{}}

iocsMapping=["pattern","value"]
cvesMapping=["external_id"]
attackersMapping=[]
malwareListMapping=["aliases"]
locationsMapping=[]
typesMapping=[]
patternMapping=[]

def readJson(jsonPath):
    with open(jsonPath,'r') as jsonFile:
        jsonObject=json.load(jsonFile)
        return jsonObject
    pass

def mappingValue(jsonObject):
    objects=jsonObject['objects']
    iocs={}
    cves,attackers,malwareList,locations,types,pattern=[],[],[],[],[],[]
    for object in objects:
        if object["type"]=="malware":
            for propertyName in malwareListMapping:
                if propertyName in object:
                    value=str(object[propertyName]) .replace("[","").replace("]","").replace("'","")
                    malwareList.append(value)
        if object["type"] == "indicator":
            for propertyName in iocsMapping:
                if propertyName in object:
                    value=str(object[propertyName]) .replace("[","").replace("]","").replace("'","")
                    name,value=value.split("=")
                    iocs[name]=value
        if object["type"] == "ipv4-addr":
            for propertyName in iocsMapping:
                if propertyName in object:
                    value=str(object[propertyName]) .replace("[","").replace("]","").replace("'","")
                    iocs[object["type"]]=value
        if object["type"] == "vulnerability":
            external_references=object["external_references"]
            for external_reference in external_references:
                if external_reference["source_name"]=="cve":
                    for propertyName in cvesMapping:
                        if propertyName in external_reference:
                            value = str(external_reference[propertyName])
                            cves.append(value)
    result=templateSelfJson
    result["malwares"]=malwareList
    result["iocs"]=iocs
    result["cves"]=cves
    return result

if __name__=="__main__":
    jsonObject=readJson('./stix2/7e1a2d7b22d42035e93a4bbbd999c0e0.json')
    result=mappingValue(jsonObject)
    print(result)