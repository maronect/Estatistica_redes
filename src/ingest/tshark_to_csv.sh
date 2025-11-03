#!/bin/bash
# Coleta de tráfego de rede e exporta para CSV

IFACE="wlp3s0" # interface de rede (`ip -br a`)
DUR=300 # duração em segundos (ex: 300 = 5 min)
OUT="data/raw/flows.csv"

mkdir -p data/raw

echo "Capturando tráfego por $DUR segundos na interface $IFACE ..."
tshark -i "$IFACE" -a duration:$DUR -T fields \
  -e frame.time_epoch \
  -e ip.src -e ip.dst \
  -e tcp.srcport -e udp.srcport \
  -e tcp.dstport -e udp.dstport \
  -e frame.len \
  -E header=y -E separator=, > "$OUT"

echo "Captura finalizada. Dados salvos em $OUT"
