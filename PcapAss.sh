#I risultati vengono inseriti nella cartella 'data/Cattura_*/Analisi' per ogni cattura

Catture=$(find data/* -maxdepth 0 -type d)
for catt in $Catture; do #per ogni cartella di cattura
	mkdir $catt/Analisi
        percorso=$catt/*.pcap*
        SUBSTRING=$(echo $percorso| cut -d'/' -f 3)
        NAME=$(echo $SUBSTRING| cut -d'.' -f 1)
        echo $NAME
        NameAss="${NAME}Ass"
        echo $NameAss
	tshark -r $catt/*.pcap* -V -o "tls.debug_file:$catt/Analisi/ssldebug.log" -o "tls.desegment_ssl_records: TRUE" -o "tls.desegment_ssl_application_data: TRUE" -o "tls.keys_list:C:/Users/Utente/.script_bash/sslkeylogfile.txt" -F pcap -w $catt/Analisi/$NameAss.pcap
done
