#/bin/bash/python3
# -*- coding: utf-8 -*-
import requests
import argparse
import json
import time
import csv

parser = argparse.ArgumentParser(description='Script for create report in .csv with alerts of tool Orion by Cytomic Panda')

parser.add_argument('-c', '--cookie', type=str, help='[Nessesary] Cookie after login in https://orion.cytomicmodel.com')
parser.add_argument('-s', '--status', type=str, help='Status 1 = In procces, Status 2 = Closed, all = not set')
parser.add_argument('-l', '--classification', type=str, help='Unclassified = 0, Confirmed Attack = 1, Investigation with no attacks detected = 2, Potential Attack = 3, all = not set')
parser.add_argument('-p', '--priority', type=str, help='Critical = 1, High = 2, Normal = 3, Low = 4, all = not set')
parser.add_argument('-a', '--assigned', type=str, help='For report to specific user(s) set email(s) in this list, Not Assigned = "none", all = not set')

(options) = parser.parse_args()

if options.cookie == None:
    print('Please set cookie first after login in https://orion.cytomicmodel.com with -c or --cookie')
    exit()
else:
    cookie = options.cookie.encode("ascii", "ignore")

try:
    status = [] if options.status == None else list(map(int,options.status.split(',')))
    classification = [] if options.classification == None else list(map(int,options.classification.split(',')))
    priority = [] if options.priority == None else list(map(int,options.priority.split(',')))
    assigned = [] if options.assigned == None else list(map(int,options.assigned.split(',')))
except:
    print('Error in parameters, try like to: -p 1,2,3')

orionUrl = 'https://orion.cytomicmodel.com'
investigationsApi = '/api/v1/cases/filter'
alertsApiByInvestigationId = '/api/v1/alerts/triggers?caseId='
alertByMuid = '/api/v1/forensics/muid/'
report = []

#Getting Investigations
headers = {
    'Cookie': cookie,
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0)'
}

#Payload to investigations
payload = {
    "statuses":status,
    "classifications":classification,
    "priorities":priority,
    "assignedToEmails":assigned
}

investigations = requests.post(orionUrl+investigationsApi, headers=headers, data=str(payload))#, verify=False, proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'})
if len(investigations.history) == 0:
    jsonInvestigations =  json.loads(investigations.text)
    count = 0
    for investigation in jsonInvestigations:
        alertsByInvestigationId = requests.get(orionUrl+alertsApiByInvestigationId+str(investigation['id']), headers=headers)
        jsonAlerts = json.loads(alertsByInvestigationId.text)
        for alert in jsonAlerts:
            infoAlert = requests.get(orionUrl+alertByMuid+str(alert['muid'])+'/events?dateFrom='+str(alert['timeStamp'])+'&dateTo='+str(alert['timeStamp']), headers=headers)
            jsonAlert = json.loads(infoAlert.text)
            for alertForensic in jsonAlert['events']:
                if str(alertForensic['timestamp'])[0:13] == str(alert['timeStamp']):
                    reportAlert = {}
                    reportAlert['Investigation'] = investigation['name']
                    reportAlert['Date'] = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(alert['timeStamp']/1000))
                    reportAlert['Computer'] = alert['machineName']
                    reportAlert['Hunting Rule'] = alert['huntingRule']
                    severity = alert['severity']
                    if severity == 1: risk = "Critical"
                    elif severity == 2: risk = "High"
                    elif severity == 3: risk = "Normal"
                    elif severity == 4: risk = "Low"
                    else: risk = "Undefined"
                    reportAlert['Risk'] = risk
                    reportAlert['Mitre'] = alert['mitre']
                    try:
                        reportAlert['parentFile'] = alertForensic['parentfilename']
                        reportAlert['parentPath'] = alertForensic['parentpath']
                    except:                        
                        reportAlert['parentFile'] = 'N/A'
                        reportAlert['parentPath'] = 'N/A'
                    try:
                        reportAlert['file'] = alertForensic['childfilename']
                        reportAlert['path'] = alertForensic['childpath']
                        reportAlert['classification'] = alertForensic['childclassification']
                    except:
                        reportAlert['file'] = 'N/A'
                        reportAlert['path'] = 'N/A'
                        reportAlert['classification'] = 'N/A'
                    try:
                        reportAlert['details'] = alertForensic['details']
                    except:
                        reportAlert['details'] = 'N/A'
                    report.append(reportAlert)
                    break        
        count += 1
        print(str(count)+'.', "Investigation:", investigation['id'], '-', "Name:", investigation['name'], '-', "Alerts:", len(jsonAlerts))
    data_file = open('csv/report.csv', 'w')
    csv_writer = csv.writer(data_file)
    count = 0
    for data in report:
        if count == 0:
            header = data.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(data.values())
    data_file.close()
    print("Report written with success")
else:
    print("Cookie expired")
