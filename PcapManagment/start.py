import csv
import pandas as pd
import os
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
check=0
"......................................................"
for cartella, sottocartelle, files in os.walk(os.getcwd()):
    s=f'{sottocartelle}'
    s=s[2:9]
    if not s== "Analisi":
           for file in files:
                  if file.endswith(".pcap"):
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
                                     employee_dict.append([string_catt,biflux,iat_pkt,pkt_size,iat_msg,msg_size])
if employee_dict:
  df = pd.DataFrame(employee_dict, columns =['CaptureNumber', 'BIFLUXS', 'ARRIVAL_TIME_PACKET','PACKET_SIZE','ARRIVAL_TIME_MSG','SIZE_MESSAGE'])
  df.to_csv("midterm.csv", index=False, sep=",")