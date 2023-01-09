#!/usr/bin/env python
# Written by CluelessAtCoding

import os
import time
import base64
import xlsxwriter
import pandas as pd

from datetime import datetime
from pathlib import Path

import argparse
parser = argparse.ArgumentParser(description='Script to parse an encoded or plain text Sonicwall Config file outputting key data to an xlsx spreadsheet',epilog="If the file is an encoded exp file ensure the --encoded argument is provided.")
parser.add_argument('sourcefile', type=str, nargs=1,help='Name of file to be parsed')
parser.add_argument('--encoded', action='store_true', help='Indicates the source file is encoded, this will cause the script to decode the contents first. If not specified it will be treated as plain text')
args = parser.parse_args()

fullfilename= ' '.join(map(str, args.sourcefile))
filename=fullfilename.split(".")
interimfile = filename[0] + ".interim"
excelfile = filename[0]  + ".xlsx"

ResultsCollection = []

with open(fullfilename, 'r') as file:
    data = file.read()

datasize = len(data)
if args.encoded:
    # Slice string to remove last 2 characters from string
    encodeddata = data[:datasize - 2]

    decodeddata = base64.b64decode(encodeddata)
    decodeddata = decodeddata.decode('utf-8')
    formatteddecoded = decodeddata.replace('&', '\n' )
else:
    formatteddecoded = data
      
formatteddecoded = formatteddecoded.replace('%20', ' ' )
formatteddecoded = formatteddecoded.replace('%3a', ':' )

f = open(interimfile, "w")
f.write(formatteddecoded)
f.close()

myconfig = {}
with open(interimfile) as config:
  for line in config.readlines():
    key, value = line.rstrip("\n").split("=")
    myconfig[key] = value

#Enumerate Information Objects and collect certain values
infoobjects = []
infoobject = {}
infoobject["Firewall Name"] = myconfig["firewallName"]
infoobject["Firewall DNS Name"] = myconfig["firewallDnsName"]
infoobject["Firewall Shortname"] = myconfig["shortProdName"]
infoobject["Firewall Build Number"] = myconfig["buildNum"]
infoobjects.append(infoobject)
ResultInfo= {}
ResultInfo["VarName"] = "infoobjects"
ResultInfo["SheetName"] = "Information"
ResultsCollection.append(ResultInfo)

#Enumerate Number of Interface Objects
ifacecount = 0
for key in myconfig:
    if (key.startswith('iface_name_')):
        ifacecount = ifacecount + 1

#Enumerate Interface Objects and collect certain values
ifaceobjects = []
iteration = 0
while iteration < ifacecount:
    ifaceobject = {}
    ifaceobject["#"] = iteration
    ifaceobject["Name"] = myconfig["iface_name_"+str(iteration)]
    ifaceobject["Zone"] = myconfig["interface_Zone_"+str(iteration)]
    ifaceobject["Comment"] = myconfig["iface_comment_"+str(iteration)]
    ifaceobject["IP Address"] = myconfig["iface_static_ip_"+str(iteration)]
    ifaceobject["Subnet Mask"] = myconfig["iface_static_mask_"+str(iteration)]
    ifaceobject["Default Gateway"] = myconfig["iface_static_gateway_"+str(iteration)]
    ifaceobject["DNS Server 1"] = myconfig["iface_static_dns1_"+str(iteration)]
    ifaceobject["DNS Server 2"] = myconfig["iface_static_dns2_"+str(iteration)]
    ifaceobject["DNS Server 3"] = myconfig["iface_static_dns3_"+str(iteration)]
    ifaceobject["MAC Address"] = myconfig["eth_mac_"+str(iteration)]
    ifaceobjects.append(ifaceobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "ifaceobjects"
ResultInfo["SheetName"] = "Interfaces"
ResultsCollection.append(ResultInfo)

#Enumerate Number of Zone Objects
zonecount = 0
for key in myconfig:
    if (key.startswith('zoneObjId_')):
        zonecount = zonecount + 1

#Enumerate Zone Objects and collect certain values
zoneobjects = []
iteration = 0
while iteration < zonecount:
    zoneobject = {}
    zoneobject["#"] = iteration
    zoneobject["ObjectID"] = myconfig["zoneObjId_"+str(iteration)]
    zoneobjects.append(zoneobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "zoneobjects"
ResultInfo["SheetName"] = "Zone Objects"
ResultsCollection.append(ResultInfo)


#Enumerate Number of IPv4 Address Objects
res = 0
for key in myconfig:
    if (key.startswith('addrObjId_')):
        res = res + 1

#Enumerate IPV4 Address Objects and collect certain values
addressobjects = []
iteration = 0
while iteration < res:
    if myconfig["addrObjType_"+str(iteration)] != "8":
        addressobject = {}
        addressobject["#"] = iteration
        addressobject["ObjectID"] = myconfig["addrObjId_"+str(iteration)]
        addressobject["Name"] = myconfig["addrObjIdDisp_"+str(iteration)]
        addressobject["Type"] = myconfig["addrObjType_"+str(iteration)].replace("1","Host").replace("2","Range").replace("4","Network").replace("8","Group")
        addressobject["Zone"] = myconfig["addrObjZone_"+str(iteration)]
        addressobject["IP"] = myconfig["addrObjIp1_"+str(iteration)]
        addressobject["IP/Mask"] = myconfig["addrObjIp2_"+str(iteration)]
        addressobject["Created Time"] = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["addrObjTimeCreated_"+str(iteration)])))
        addressobject["Updated Time"] = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["addrObjTimeUpdated_"+str(iteration)])))
        addressobjects.append(addressobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "addressobjects"
ResultInfo["SheetName"] = "Address Objects"
ResultsCollection.append(ResultInfo)

#Enumerate Address Groups and collect certain values
addressgroups = []
iteration = 0
while iteration < res:
    if myconfig["addrObjType_"+str(iteration)] == "8":
        addressgroup = {}
        addressgroup["#"] = iteration
        addressgroup["ObjectID"] = myconfig["addrObjId_"+str(iteration)]

        groupmembers = []    
        for key, value in myconfig.items():
            if value == addressgroup["ObjectID"]:
                if key.startswith("addro_grpToGrp_"):
                    membername=myconfig[key.replace("addro_grpToGrp_","addro_atomToGrp_")]
                    groupmembers.append(membername)
        addressgroup["Name"] = myconfig["addrObjIdDisp_"+str(iteration)]
        addressgroup["Type"] = myconfig["addrObjType_"+str(iteration)].replace("8","Group")
        addressgroup["Members"] = groupmembers
        addressgroups.append(addressgroup)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "addressgroups"
ResultInfo["SheetName"] = "Address Groups"
ResultsCollection.append(ResultInfo)

#Enumerate Number of IPv6 Address Objects
resv6 = 0
for key in myconfig:
    if (key.startswith('addrObjV6Id_')):
        resv6 = resv6 + 1
     
#Enumerate IPV6 Address Objects and collect certain values
addressobjectsv6 = []
iteration = 0
while iteration < resv6:
    if myconfig["addrObjV6Type_"+str(iteration)] != "8":
        addressobjectv6 = {}
        addressobjectv6["#"] = iteration
        addressobjectv6["ObjectID"] = myconfig["addrObjV6Id_"+str(iteration)]
        addressobjectv6["Name"] = myconfig["addrObjV6IdDisp_"+str(iteration)]
        addressobjectv6["Type"] = myconfig["addrObjV6Type_"+str(iteration)].replace("1","Host").replace("2","Range").replace("4","Network").replace("8","Group")
        addressobjectv6["Zone"] = myconfig["addrObjV6Zone_"+str(iteration)]
        addressobjectv6["IP"] = myconfig["addrObjV6Ip1_"+str(iteration)]
        addressobjectv6["IP/Mask"] = myconfig["addrObjV6Ip2_"+str(iteration)]
        addressobjectsv6.append(addressobjectv6)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "addressobjectsv6"
ResultInfo["SheetName"] = "Address Objects IPv6"
ResultsCollection.append(ResultInfo)

#Enumerate IPv6 Address Groups and collect certain values
addressgroupsv6 = []
iteration = 0
while iteration < resv6:
    if myconfig["addrObjV6Type_"+str(iteration)] == "8":
        addressgroupv6 = {}
        addressgroupv6["#"] = iteration
        addressgroupv6["ObjectID"] = myconfig["addrObjV6Id_"+str(iteration)]
        groupmembersv6 = []    
        for key, value in myconfig.items():
            if value == addressgroupv6["ObjectID"]:
                if key.startswith("addro_grpToGrp_"):
                    membername=myconfig[key.replace("addro_grpToGrp_","addro_atomToGrp_")]
                    groupmembersv6.append(membername)
        addressgroupv6["Name"] = myconfig["addrObjV6IdDisp_"+str(iteration)]
        addressgroupv6["Type"] = myconfig["addrObjV6Type_"+str(iteration)].replace("8","Group")
        addressgroupv6["Members"] = groupmembersv6
        addressgroupsv6.append(addressgroupv6)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "addressgroupsv6"
ResultInfo["SheetName"] = "Address Groups IPv6"
ResultsCollection.append(ResultInfo)

#Enumerate Number of IPv4 Access Rules
rulecount = 0
for key in myconfig:
    if (key.startswith('policyName_')):
        rulecount = rulecount + 1
     
#Enumerate IPv4 Access Rules and collect certain values
accessrules = []
iteration = 0
while iteration < rulecount:
    accessrule = {}
    accessrule["#"] = iteration
    accessrule["From"] = myconfig["policySrcZone_"+str(iteration)]
    accessrule["To"] = myconfig["policyDstZone_"+str(iteration)]
    accessrule["Source"] = myconfig["policySrcNet_"+str(iteration)]
    accessrule["Destination"] = myconfig["policyDstNet_"+str(iteration)]
    accessrule["Service"] = myconfig["policyDstSvc_"+str(iteration)]
    accessrule["Action"] = myconfig["policyAction_"+str(iteration)].replace("2","Allow").replace("0","Deny")
    accessrule["Enabled"] = myconfig["policyEnabled_"+str(iteration)].replace("0","No").replace("1","Yes")
    accessrule["Logging"] = myconfig["policyLog_"+str(iteration)].replace("1","Yes")
    accessrule["Comment"] = myconfig["policyComment_"+str(iteration)]
    accessrule["Hit Count"] = int(myconfig["policyHitCount_"+str(iteration)])
    accessrule["Created Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeCreated_"+str(iteration)])))
    accessrule["Updated Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeUpdated_"+str(iteration)])))
    accessrule["Last Hit Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeLastHit_"+str(iteration)])))
    accessrules.append(accessrule)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "accessrules"
ResultInfo["SheetName"] = "IPv4 Access Rules"
ResultsCollection.append(ResultInfo)

#Enumerate Number of IPv6 Access Rules
rulecountv6 = 0
for key in myconfig:
    if (key.startswith('policyNameV6_')):
        rulecountv6 = rulecountv6 + 1
     
#Enumerate IPv6 Access Rules and collect certain values
accessrulesv6 = []
iteration = 0
while iteration < rulecountv6:
    accessrulev6 = {}
    accessrulev6["#"] = iteration
    accessrulev6["From"] = myconfig["policySrcZoneV6_"+str(iteration)]
    accessrulev6["To"] = myconfig["policyDstZoneV6_"+str(iteration)]
    accessrulev6["Source"] = myconfig["policySrcNetV6_"+str(iteration)]
    accessrulev6["Destination"] = myconfig["policyDstNetV6_"+str(iteration)]
    accessrulev6["Service"] = myconfig["policyDstSvcV6_"+str(iteration)]
    accessrulev6["Action"] = myconfig["policyActionV6_"+str(iteration)].replace("2","Allow").replace("0","Deny")
    accessrulev6["Enabled"] = myconfig["policyEnabledV6_"+str(iteration)].replace("0","No").replace("1","Yes")
    accessrulev6["Logging"] = myconfig["policyLogV6_"+str(iteration)].replace("1","Yes")
    accessrulev6["Comment"] = myconfig["policyCommentV6_"+str(iteration)]
    accessrulev6["Hit Count"] = int(myconfig["policyHitCountV6_"+str(iteration)])
    accessrulev6["Created Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeCreatedV6_"+str(iteration)])))
    accessrulev6["Updated Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeUpdatedV6_"+str(iteration)])))
    accessrulev6["Last Hit Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["policyTimeLastHitV6_"+str(iteration)])))
    accessrulesv6.append(accessrulev6)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "accessrulesv6"
ResultInfo["SheetName"] = "IPv6 Access Rules"
ResultsCollection.append(ResultInfo)

#Enumerate Number of Service Objects
servicecount = 0
for key in myconfig:
    if (key.startswith('svcObjId_')):
        servicecount = servicecount + 1
     
#Enumerate Service Objects and collect certain values
serviceobjects = []
iteration = 0
while iteration < servicecount:
    if myconfig["svcObjType_"+str(iteration)] != "2":
        serviceobject = {}
        serviceobject["#"] = iteration
        serviceobject["ObjectID"] = myconfig["svcObjId_"+str(iteration)]
        serviceobject["Protocol"] = myconfig["svcObjIpType_"+str(iteration)].replace("108","IPComp").replace("50","ESP").replace("6","TCP").replace("17","UDP").replace("41","IPv6 Encapsulation").replace("1","ICMP").replace("2","IGMP").replace("47","GRE").replace("58","IPv6 ICMP")
        serviceobject["Port Start"] = int(myconfig["svcObjPort1_"+str(iteration)])
        serviceobject["Port End"] = int(myconfig["svcObjPort2_"+str(iteration)])
        serviceobject["Created Time"] = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["svcObjTimeCreated_"+str(iteration)])))
        serviceobject["Updated Time"] = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["svcObjTimeUpdated_"+str(iteration)])))
        serviceobjects.append(serviceobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "serviceobjects"
ResultInfo["SheetName"] = "Service Objects"
ResultsCollection.append(ResultInfo)

#Enumerate Service Groups and collect certain values
servicegroups = []
iteration = 0
while iteration < servicecount:
    if myconfig["svcObjType_"+str(iteration)] == "2":
        servicegroup = {}
        servicegroup["#"] = iteration
        servicegroup["ObjectID"] = myconfig["svcObjId_"+str(iteration)]

        groupmembers = []    
        for key, value in myconfig.items():
            if value == servicegroup["ObjectID"]:
                if key.startswith("so_grpToGrp_"):
                    membername=myconfig[key.replace("so_grpToGrp_","so_atomToGrp_")]
                    groupmembers.append(membername)
        servicegroup["Name"] = myconfig["svcObjId_"+str(iteration)]
        servicegroup["Members"] = groupmembers
        servicegroups.append(servicegroup)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "servicegroups"
ResultInfo["SheetName"] = "Service Groups"
ResultsCollection.append(ResultInfo)

#Enumerate Number of NAT policies
natcount = 0
for key in myconfig:
    if (key.startswith('natPolicyName_')):
        natcount = natcount + 1
     
#Enumerate NAT Policies and collect certain values
natobjects = []
iteration = 0
while iteration < natcount:
    natobject = {}
    natobject["#"] = iteration
    natobject["Original Source"] = myconfig["natPolicyOrigSrc_"+str(iteration)]
    natobject["Translated Source"] = myconfig["natPolicyTransSrc_"+str(iteration)]
    natobject["Original Destination"] = myconfig["natPolicyOrigDst_"+str(iteration)]
    natobject["Translated Destination"] = myconfig["natPolicyTransDst_"+str(iteration)]
    natobject["Original Service"] = myconfig["natPolicyOrigSvc_"+str(iteration)]
    natobject["Translated Service"] = myconfig["natPolicyTransSvc_"+str(iteration)]
    natobject["Enabled"] = myconfig["natPolicyEnabled_"+str(iteration)].replace("1","Yes").replace("0","No")
    natobject["Hit Count"] = int(myconfig["natPolicyHitCount_"+str(iteration)])
    natobject["Comment"] = myconfig["natPolicyComment_"+str(iteration)]
    natobject["Created Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["natPolicyTimeCreated_"+str(iteration)])))
    natobject["Updated Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["natPolicyTimeUpdated_"+str(iteration)])))
    natobject["Last Hit Time"]=time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(int(myconfig["natPolicyTimeLastHit_"+str(iteration)])))
    natobjects.append(natobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "natobjects"
ResultInfo["SheetName"] = "NAT Objects"
ResultsCollection.append(ResultInfo)

#Enumerate Number of VPN policies
vpncount = 0
for key in myconfig:
    if (key.startswith('vpnPolicyType_')):
        vpncount = vpncount + 1
     
#Enumerate VPN Policies and collect certain values
vpnobjects = []
iteration = 0
while iteration < vpncount:
    vpnobject = {}
    vpnobject["#"] = iteration
    vpnobject["Name"] = myconfig["ipsecName_"+str(iteration)]
    vpnobject["IPSed Primary Gateway"] = myconfig["ipsecGwAddr_"+str(iteration)]
    vpnobject["IPSec Secondary Gateway"] = myconfig["ipsecSecGwAddr_"+str(iteration)]
    vpnobject["Phase 1 Local ID"] = myconfig["ipsecPhase1LocalId_"+str(iteration)]
    vpnobject["Phase 1 Remote ID"] = myconfig["ipsecPhase1RemoteId_"+str(iteration)]
    vpnobject["Local Network"] = myconfig["ipsecLocalNetwork_"+str(iteration)]
    vpnobject["Remote Netork"] = myconfig["ipsecRemoteNetwork_"+str(iteration)]
    vpnobject["Disabled"] = myconfig["ipsecSaDisabled_"+str(iteration)]
    vpnobjects.append(vpnobject)
    iteration = iteration + 1
ResultInfo= {}
ResultInfo["VarName"] = "vpnobjects"
ResultInfo["SheetName"] = "VPN Objects"
ResultsCollection.append(ResultInfo)

# Output Results to XLSX
# Create a Pandas Excel writer using XlsxWriter as the engine.
writer = pd.ExcelWriter(excelfile, engine='xlsxwriter')

for section in ResultsCollection:
    # Create Pandas dataframes from parsed data
    resultdata=globals()[section['VarName']]
    xlsxsheetname=section['SheetName']
    df = pd.DataFrame(resultdata)

    # Write the dataframe data to XlsxWriter. Turn off the default header and
    # index and skip one row to allow us to insert a user defined header.
    df.to_excel(writer, sheet_name=xlsxsheetname, startrow=1, header=False, index=False)

    # Get the xlsxwriter workbook.
    workbook = writer.book

    #Get the AddressObjects worksheet objects
    worksheet = writer.sheets[xlsxsheetname]
    # Get the dimensions of the dataframe.
    (max_row, max_col) = df.shape
    # Create a list of column headers, to use in add_table().
    column_settings = [{'header': column} for column in df.columns]
    # Add the Excel table structure. Pandas will add the data.
    worksheet.add_table(0, 0, max_row, max_col - 1, {'columns': column_settings})

    for column in df:
        column_length = max(df[column].astype(str).map(len).max(), len(column))
        col_idx = df.columns.get_loc(column)
        worksheet.set_column(col_idx, col_idx, column_length)

# Close the Pandas Excel writer and output the Excel file.
writer.close()

# Delete Interim File

os.remove(interimfile) 