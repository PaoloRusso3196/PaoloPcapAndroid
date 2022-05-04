import pandas as pd
import time
import os
import numpy as np
import scipy
import ast
import matplotlib.pyplot as plt
path="PCAP.csv"
list_FtrsActual=[]
list_StreamActual=[]
list_Ftrs_filtred=[]
list_Ftrs=["PACKET_SIZE","ARRIVAL_TIME_PACKET","SIZE_MESSAGE","ARRIVAL_TIME_MSG"]
TypeList=["App_Name","Activty"]
ValueStreamList=[0,1]
cattura=1
"----------------------------------------------------------------------"
def PloatCdf(list_element,type_name,labelName):
    List_Feature=[]
    for x in list_element:
       List_Feature.append(x)
    
    List_Feature=list(map(float,List_Feature))
    List_Feature.sort()
    cdf = np.cumsum(List_Feature)
    plt.plot(List_Feature,cdf, label =type_name)
    
    plt.xlabel("Values "+labelName)
    plt.ylabel("Probability Values")
    #plt.title("CDF  of "+ type_name)
    plt.legend()
    #plt.show()
  
   
    
#1)CASO IN CUI VADO A CONSIDERARE IL DATAFRAME PER APP E PER LE ATTIVITA'
"-----------------------------------------------------------------------"


for s in list_Ftrs:
   z=-1
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
                          ftrs_csv=str(filtered_df_capture[s][i])
                          list_FtrsActual=ast.literal_eval((ftrs_csv))
                          stream_csv=str( filtered_df_capture["TYPE_STREAM"][i])
                          list_StreamActual=ast.literal_eval((stream_csv))
                  for steamAct,ftrsAct in zip(list_StreamActual,list_FtrsActual):
                           if steamAct== 1:
                               list_Ftrs_filtred.append(ftrsAct)
                  PloatCdf(list_Ftrs_filtred,type_name,s)
                  list_Ftrs_filtred.clear()
                  list_StreamActual.clear()
                  list_FtrsActual.clear()
   plt.show()