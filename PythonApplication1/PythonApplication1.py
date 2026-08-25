#"C:\\Users\\shaha\\source\\repos\\PythonApplication1\\pythontest.txt"
import json
import time
from urllib import response
import requests
results = {}
def readfile(file_name):
    with open(file_name,"r") as f:

        for line in f:
         line = line.strip()
         y=line.find(":")+1
         x=line[:y-1]
         results[line[y:]]={"name":x,"value":line[y:],"status":""}
        with open("C:\\Users\\shaha\\source\\repos\\PythonApplication1\\jsonfile.json","w") as jsonfile:
            json.dump(results,jsonfile,indent=2) #הכנסת האיבר לגייסון

def virustotalhash(jsonfile):
    api="ee6ea0b4c9885f5b75ed60a4f16d9df873f6c3ddec9066c7d895412dcdddb437"
    
    headers = {
    "accept": "application/json",
    "x-apikey": api
}
    with open ("C:\\Users\\shaha\\source\\repos\\PythonApplication1\\jsonfile.json","r") as jsonfile:
        file = json.load(jsonfile) #טעינה למשתנה כדי לעבוד 
    with open ("C:\\Users\\shaha\\source\\repos\\PythonApplication1\\jsonfile.json","w") as jsonfile:
        for fhash in file.values():
            key=fhash.get("value")
            url=f"https://www.virustotal.com/api/v3/files/{key}"
            print("Checking the hash == ",key)
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    result_data = response.json()
                    stats = result_data.get("data", {}).get("attributes", {})#.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    print(stats.keys())
                    print(f" ->{malicious_count}")
                    fhash["status"]=stats
                elif response.status_code == 404:
                    print(" ->Hash not found.")
                else:
                    print(f" ->Connection failed: {response.status_code}")
            except Exception as e:
                print(f" -> תקלת חיבור: {e}")
            print("-" * 40)
            time.sleep(5)
        json.dump(file,jsonfile,indent=2)
    print("File saved!")          



readfile("C:\\Users\\shaha\\source\\repos\\PythonApplication1\\pythontest.txt")
virustotalhash("C:\\Users\\shaha\\source\\repos\\PythonApplication1\\jsonfile.json")

    
