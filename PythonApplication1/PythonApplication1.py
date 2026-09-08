#"C:\\Users\\shaha\\source\\repos\\PythonApplication1\\pythontest.txt"
import json
import time
import csv
import os
from urllib import response
import requests
results = {}
def readfile(file_name):
    print("Reading Opswat report..")          
    print("-" * 40)
    start_infected="--------Infected Files--------"
    start_skipped="--------Skipped Files or Errors--------"
    with open(file_name,"r") as f:
        for line in f:
            if line.strip() == start_infected or line.strip() ==start_skipped:
                break                
        for line in f:
         line = line.strip()
         if "Filename" in line:
             y=line.find(":")+1
             filename=line[y+1:]
             line=f.readline()
             line = line.strip()
             y=line.find(":")+1
             vhash=line[y+1:]
             f.readline()
             if vhash in results:
                 results[vhash]["filename"].append(filename)
             else:
                 results[vhash]={"filename":[filename],"hash":vhash,"status":""}
    script_dir = os.path.dirname(os.path.abspath(__file__))  
    freport = os.path.join(script_dir, "Allhash.json")
    with open(freport,"w") as jsonfile:
         json.dump(results,jsonfile,indent=2) #הכנסת האיבר לגייסון
    return freport

def whitelistloading(whitelist_path):
    #open approved file to set
    print("Loading Whitelist files...")
    print("-" * 40)
    values={""}
    with open(whitelist_path,"r")as file:
        for vhash in file:
            vhash=vhash.strip()
            values.add(vhash)
    return values
        
def virustotalhash(whitelist_path,allhash):
    
    api="1c42215d75a8792b67e9a6dcac825db4b84e28a1109dcbc36ace0c75650f3015"
    
    headers = {
    "accept": "application/json",
    "x-apikey": api
}
    with open (allhash,"r") as jsonfile:
        file = json.load(jsonfile) #טעינה למשתנה כדי לעבוד 
    with open (allhash,"w") as jsonfile:
        values=whitelistloading(whitelist_path)
        error=False
        for fhash in file.values():
            key=fhash.get("hash")
            url=f"https://www.virustotal.com/api/v3/files/{key}"
            print("Checking == ",key)
            if key in values:
                print("[WL]-> File is Whitelisted")
                fhash["status"]="Whitelisted"
            else:
                try:
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                       result_data = response.json()
                       stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                       malicious_count = stats.get("malicious", 0)
                       print("[VirusTotal] ->")
                       for key, value in stats.items():
                         print(f"{key:<20} | {value}")
                       fhash["status"]=stats
                    elif response.status_code == 404:
                     print("[VirusTotal] -> Hash not found")
                     print("[WL]         -> Hash not found")
                     fhash["status"]= "N/A"
                    else:
                     print(f"[VirusTotal] ->Connection failed: {response.status_code}")
                     error=True
                except Exception as e:
                   error=True
                   print(f" ->ERROR: {e}")
            print("-" * 40)
            time.sleep(3)
        json.dump(file,jsonfile,indent=2) 
        #writing final report
        print("Creating final report...")
        script_dir = os.path.dirname(os.path.abspath(__file__))  
        freport = os.path.join(script_dir, "final_report.csv")
        with open(freport,"w", newline='', encoding='utf-8')as report:
            fields=["Hash","Paths","Status"]
            writer = csv.DictWriter(report, fieldnames=fields)
            writer.writeheader()
            for fhash in file.values():
                status = fhash.get("status", "")
                #malicious_count = 0
                if isinstance(status, dict):
                  malicious_count = status.get("malicious", 0)
                if status == "N/A" or malicious_count >0:
                      path= " | ".join(fhash["filename"])
                      writer.writerow({"Hash": fhash.get("hash"),"Paths": path,"Status": status})
    if error ==True:
        print("NOTE! an error happend will runnin, some results may not appear")
    print("File saved!")  
    return freport





    
