Catture=$(find data/*/Analisi -maxdepth 0 -type d)

for catt in $Catture; do
	rm -rf $Catture
done
