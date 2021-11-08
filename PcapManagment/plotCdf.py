import pandas as pd
import time
import os
import numpy as np
import scipy
import ast
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d
path="C:/Users/Utente/Desktop/FiltraggioPcap/PCAP.csv"
list_IatPkt=[]
list_IatMsg=[]
list_PktSize=[]
list_MsgSize=[]
cattura=1
catt=1
i=0 
"----------------------------------------------------------------------"

def find_substring(string, start, end):
    len_until_end_of_first_match = string.find(start) + len(start)
    after_start = string[len_until_end_of_first_match:]
    return string[string.find(start) + len(start):len_until_end_of_first_match + after_start.find(end)]

"-----------------------------------------------------------------------"
def PloatCdf(List_element,type_feature,xlabel,ylabel):
    indice=1
    k=0
    List_Features=[]
 
    for i in List_element:
                catt_str="c"+str(indice)
               # print(t,catt_str)
                len_ind=len(catt_str)
                st_catt=i[0:len_ind]
                if  not st_catt==catt_str:
                    #print(st_catt,catt_str)
                    #print(indice,v)
                    print(List_Features)
                    List_Features=list(map(float,List_Features))
                    List_Features.sort()
                    cumulative = np.cumsum(List_Features)
                    plt.plot(cumulative,label=type_feature+str(indice))
                    plt.xlabel(xlabel)
                    plt.ylabel(ylabel)        
                    List_Features.clear()
                    indice=int(indice)+1
                catt_str="c"+str(indice)
                a=find_substring(i,catt_str,type_feature)
                List_Features=ast.literal_eval((a))
   
    
   # print(z) 
    
   # print(indice)
   # print(List_Features)
    List_Features=list(map(float,List_Features))
    List_Features.sort()
    cumulative = np.cumsum(List_Features)
    plt.plot(cumulative,label=type_feature+str(indice))
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)        
    List_Features.clear()    
    plt.legend()
    plt.show()            
   
    
    
"-----------------------------------------------------------------------"

df = pd.read_csv(path, delimiter=';')
while True:
    cattura_str="c"+str(cattura)
    print("Elaborazione Cattura "+cattura_str)
    df_capture=df['CaptureNumber']==cattura_str
    filtered_df_capture = df[df_capture]
    if len( filtered_df_capture)>0:
                  for i in filtered_df_capture.index:
                      
                          IatPkt_csv=cattura_str+str(df["ARRIVAL_TIME_PACKET"][i])+str("IatPkt")
                          list_IatPkt.append(IatPkt_csv)
                          
                          SizePkt_csv=cattura_str+str(df["PACKET_SIZE"][i])+str("PktSize")
                          list_PktSize.append(SizePkt_csv)
                          
                          SizeMsg_csv=cattura_str+str(df["SIZE_MESSAGE"][i])+str("MsgSize")
                          list_MsgSize.append(SizeMsg_csv)
                          
                          IatMsg_csv=cattura_str+str(df["ARRIVAL_TIME_MSG"][i])+str("IatMsg")
                          list_IatMsg.append(IatMsg_csv)
                          
                                
    
    
    else:
                       break
    cattura=int(cattura)+1                      
                   

#print(t)    
PloatCdf(list_IatPkt,"IatPkt","Number Of Packet","IAT Packet")
PloatCdf(list_PktSize,"PktSize","Number Of Packet","Size Packet")
PloatCdf(list_MsgSize,"MsgSize","Number Of Msg","Size Msg")
PloatCdf(list_IatMsg,"IatMsg","Number Of Msg","IAT Msg")    
  
    