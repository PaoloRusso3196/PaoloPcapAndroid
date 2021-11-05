#I risultati vengono inseriti nella cartella 'data/Cattura_*/Analisi' per ogni cattura

Catture=$(find data/* -maxdepth 0 -type d)
for catt in $Catture; do #per ogni cartella di cattura
	mkdir $catt/Analisi
	tshark -r $catt/*.pcap* -V -o "ssl.debug_file:$catt/Analisi/ssldebug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list: C:\Users\Utente\.script_bash\sslkeylogfile.txt" > $catt/Analisi/PcapAss.pcap
done

