# Uso de estatistica para reconhecimento de padrões em rede

sudo bash src/ingest/tshark_to_csv.sh

python src/detect/anomaly.py --in data/raw/flows.csv --out outputs/alerts.csv