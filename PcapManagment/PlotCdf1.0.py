import pandas as pd
import time
import os
import numpy as np
import scipy
import ast
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d
path="C:/Users/Utente/Desktop/PcapManage/PCAP.csv"
list_IatPkt=[]
list_IatMsg=[]
list_PktSize=[]
list_MsgSize=[]
TypeList=["App_Name","Activty"]
cattura=1
"----------------------------------------------------------------------"
def PloatCdf(list_element):
    List_Feature=[]
    for x in list_element:
       List_Feature.append(x)
    
    List_Feature=list(map(float,List_Feature))
    List_Feature.sort()
    
  
    cumulative = np.cumsum(List_Feature)
    plt.plot(cumulative,label="cattura_csv")
    plt.show()
    
    
#1)CASO IN CUI VADO A CONSIDERARE IL DATAFRAME PER APP O PER ATTIVITA'
"-----------------------------------------------------------------------"
df = pd.read_csv(path, delimiter=';')
df1= pd.read_csv(path, delimiter=';')

for x in TypeList:
    
    type_value=df1.drop_duplicates(subset =x)
    for type_i in type_value.index:
        type_name=str(df1[x][type_i])
        df_capture=df[x]==type_name
        filtered_df_capture = df[df_capture]
        if len( filtered_df_capture)>0:
                  for i in filtered_df_capture.index:
                          iatpkt_csv=str(df["ARRIVAL_TIME_PACKET"][i])
                          list_IatPkt=ast.literal_eval((iatpkt_csv))
                          pktsz_csv=str(df["PACKET_SIZE"][i])
                          list_PktSize=ast.literal_eval((pktsz_csv))
                          iatmsg_csv=str(df["ARRIVAL_TIME_MSG"][i])
                          list_IatMsg=ast.literal_eval((iatmsg_csv))
                          msgsz_csv=str(df["SIZE_MESSAGE"][i])
                          list_MsgSize=ast.literal_eval((msgsz_csv))
                 #print(list_IatPkt)
                  #PloatCdf(list_IatPkt)
                  #PloatCdf(list_PktSize)
                  #PloatCdf(list_IatMsg)
                  #PloatCdf(list_MsgSize)
                  list_IatPkt.clear()
                  list_PktSize.clear()
                  list_IatMsg.clear()
                  list_MsgSize.clear()
"..........................................................................................."                  
#2)CASO IN CUI VADO A CONSIDERARE IL DATAFRAME PRIMA PER APP E POI PER L' ATTIVITA' ASSOCIATA
"--------------------------------------------------------------------------------"
app=df1.drop_duplicates(subset =TypeList[0])
#print(app)
for app_i in app.index:
    appName=str(df1[TypeList[0]][app_i])
    df_capture=df[TypeList[0]]==appName
    filtered_df_capture = df[df_capture]
    #print(filtered_df_capture[TypeList[1]])
    activity=filtered_df_capture.drop_duplicates(subset =TypeList[1])
    #print(activity[TypeList[1]])
    for activity_i in activity.index:
          
          Activity=str(activity[TypeList[1]][activity_i])
          df_capAct=filtered_df_capture[TypeList[1]]==Activity
          filtered_AppAct = filtered_df_capture[df_capAct]
          
          print(filtered_AppAct)
          if len(filtered_AppAct)>0:
                    for i in filtered_AppAct.index:
                            iatpkt_csv=str(df["ARRIVAL_TIME_PACKET"][i])
                            list_IatPkt=ast.literal_eval((iatpkt_csv))
                            pktsz_csv=str(df["PACKET_SIZE"][i])
                            list_PktSize=ast.literal_eval((pktsz_csv))
                            iatmsg_csv=str(df["ARRIVAL_TIME_MSG"][i])
                            list_IatMsg=ast.literal_eval((iatmsg_csv))
                            msgsz_csv=str(df["SIZE_MESSAGE"][i])
                            list_MsgSize=ast.literal_eval((msgsz_csv))
                    #print(list_IatPkt)
                    #PloatCdf(list_IatPkt)
                    #PloatCdf(list_PktSize)
                    #PloatCdf(list_IatMsg)
                    #PloatCdf(list_MsgSize)
                    list_IatPkt.clear()
                    list_PktSize.clear()
                    list_IatMsg.clear()
                    list_MsgSize.clear()
 
        
    
    
         
         