import csv
import pandas as pd
import os
import re
import json
from operator import itemgetter
#load_layer('tls')
"------------declare vairiables--------------------"
ip_source="NULL"
ip_dst="NULL"
pkt_size=0
actual_time_pkt=0
last_time_pkt=0
iat_pkt=0
load="NULL"
msg_size=0
actual_time_msg=0
last_time_msg=0
iat_msg=0
biflux="null"
employee_dict=[]
cattura=0
src_port=0
dst_port=0
proto_type=0
protocol="NULL"
list_activity=[]
list_AppName=[]
pcap_index=0
i=0
"......................................................"
for cartella, sottocartelle, files in os.walk(os.getcwd()):
    s=f'{sottocartelle}'
    s=s[2:9]
    if not s== "Analisi":
           for file in files:
                  if i==0:
                     if file.endswith(".json"):
                        print("Okk")
                        directory_json=f'{cartella}'+"/"+file
                        with open(directory_json) as f:
                             activity_info= json.load(f)
                             for p in activity_info:
                                    print(p["ACTIVITY"])
                                    list_activity.append(p["ACTIVITY"])
                                    list_AppName.append(p["APP"])



                     if file.endswith(".csv"):
                         directory_csv=f'{cartella}'+"/"+file
                         print(directory_csv)
                         os.remove(directory_csv)
                  if file.endswith(".pcap"):
                          #end = file.find('.pcap')
                          #app_name =file[0:end]
                          app_name =list_AppName[pcap_index]
                          label_activity=list_activity[pcap_index]
                          pcap_index=pcap_index+1
                          print(app_name,label_activity)
                          i=0
                          #employee_dict.clear()
                          cattura=cattura+1
                          fild=((f'{cartella}'+"/"+file))
                          print(fild)
                          a=rdpcap(fild)
                          for packet in a:
                                     pkt=a[i]
                                     #pkt.show()
                                     if i==0:
                                         actual_time_pkt=pkt.time
                                         last_time_pkt=0
                                     else:
                                         actual_time_pkt=pkt.time
                                     iat_pkt=(actual_time_pkt-last_time_pkt)
                                     pkt_size=len(pkt)
                                     ip_source=str(pkt[IP].src)
                                     ip_dst=str(pkt[IP].dst)
                                     biflux=ip_source+"-"+ip_dst
                                     src_port=pkt[IP].sport
                                     dst_port=pkt[IP].dport
                                     protocol_type=pkt[IP].proto
                                     if protocol_type== 6:
                                               protocol='TCP'
                                     elif protocol_type== 17:
                                               protocol='UDP'
                                     if pkt.haslayer(Raw):
                                            load=(pkt[Raw].load)
                                            msg_size=len(load)
                                            if i==0:
                                                actual_time_msg=pkt.getlayer(Raw).time
                                                last_time_msg=0
                                            else:
                                                actual_time_msg=pkt.getlayer(Raw).time
                                                #print(actual_time_msg)

                                            iat_msg=(actual_time_msg-last_time_msg)
                                            last_time_pkt=actual_time_pkt
                                            last_time_msg=actual_time_msg
                                     i=i+1
                                     string_catt="c"+str(cattura)
                                     employee_dict.append([app_name,label_activity,string_catt,biflux,protocol,src_port,dst_port,iat_pkt,pkt_size,iat_msg,msg_size])
if employee_dict:
  df = pd.DataFrame(employee_dict, columns =['App_Name','Activity','CaptureNumber', 'BIFLUXS','PROTOCOL','SOURCE_PORT','DESTINATION_PORT','ARRIVAL_TIME_PACKET','PACKET_SIZE','ARRIVAL_TIME_MSG','SIZE_MESSAGE'])
  df.sort_values(by=['CaptureNumber','BIFLUXS'], inplace = True)
  #df.to_csv("midterm.csv", index=False, sep=",")
  print(df)
  list_IatPkt=[]
  list_IatMsg=[]
  list_PktSize=[]
  list_MsgSize=[]
  list_SrcPrt=[]
  list_DstPrt=[]
  list_Protocol=[]
  employee_dict=[]
  cattura=1
  print(employee_dict)
  while True:
        cattura_str="c"+str(cattura)
        print("Elaborazione Cattura "+cattura_str)
        df_capture=df['CaptureNumber']==cattura_str
        filtered_df_capture = df[df_capture]
        if len( filtered_df_capture)>0:
                      list_biflux=(filtered_df_capture.drop_duplicates(subset = "BIFLUXS"))
                      for i in list_biflux.index:
                                bflx=str(list_biflux["BIFLUXS"][i])
                                AppName=(df["App_Name"][i])
                                ActivtyLbl=(df["Activity"][i])
                                #print(bflx)
                                df_mask=filtered_df_capture['BIFLUXS']==bflx
                                filtered_df = filtered_df_capture[df_mask]
                                #print(filtered_df)
                                for i in filtered_df.index:
                                         IatPkt=(df["ARRIVAL_TIME_PACKET"][i])
                                         SizePkt=(df["PACKET_SIZE"][i])
                                         IatMsg=(df["ARRIVAL_TIME_MSG"][i])
                                         SizeMsg=(df["SIZE_MESSAGE"][i])
                                         SrcPrt=(df["SOURCE_PORT"][i])
                                         DstPrt=(df["DESTINATION_PORT"][i])
                                         Prtl=(df["PROTOCOL"][i])
                                         list_IatPkt.append(IatPkt)
                                         list_PktSize.append(SizePkt)
                                         list_IatMsg.append(IatMsg)
                                         list_MsgSize.append(SizeMsg)
                                         list_SrcPrt.append(SrcPrt)
                                         list_DstPrt.append(DstPrt)
                                list_SrcPrt = list(set(list_SrcPrt))
                                list_DstPrt = list(set(list_DstPrt))
                                IatPktList=",".join(map(str,list_IatPkt))
                                SizePktList=",".join(map(str,list_PktSize))
                                IatMsgList=",".join(map(str,list_IatMsg))
                                SizeMsgList=",".join(map(str,list_MsgSize))
                                SrcPrtList=",".join(map(str,list_SrcPrt))
                                DstPrtList=",".join(map(str,list_DstPrt))
                                IatPktList="["+IatPktList+"]"
                                SizePktList="["+SizePktList+"]"
                                IatMsgList="["+IatMsgList+"]"
                                SizeMsgList="["+SizeMsgList+"]"
                                SrcPrtList="["+SrcPrtList+"]"
                                DstPrtList="["+DstPrtList+"]"
                                list_IatPkt.clear()
                                list_PktSize.clear()
                                list_IatMsg.clear()
                                list_MsgSize.clear()
                                list_SrcPrt.clear()
                                list_DstPrt.clear()
                                employee_dict.append([AppName,ActivtyLbl,cattura_str,bflx,Prtl,SrcPrtList,DstPrtList,IatPktList,SizePktList,IatMsgList,SizeMsgList])
        else:
                       break
        cattura=int(cattura)+1    
  #print(employee_dict)
  a = pd.DataFrame(employee_dict, columns =['App_Name','Activty','CaptureNumber', 'BIFLUXS','PROTOCOL','SOURCE_PORT','DESTINATION_PORT','ARRIVAL_TIME_PACKET','PACKET_SIZE','ARRIVAL_TIME_MSG','SIZE_MESSAGE'])
  a.to_csv("PCAP.csv", index=False, sep=";",mode="w")
 
  