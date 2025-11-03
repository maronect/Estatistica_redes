"""
Módulo de análises estatísticas complementares para tráfego de rede.
Inclui:
 - Correlação entre features
 - Entropia de IPs de destino
 - Distribuição de cauda (heavy-tailed)
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from scipy.stats import entropy

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

# 1. Correlação entre features
def plot_correlation(fe: pd.DataFrame):
    """Gera um heatmap de correlação entre as principais features de tráfego."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = ensure_dir("outputs/statistics")
    corr = fe.corr(numeric_only=True)
    plt.figure(figsize=(6, 5))
    plt.imshow(corr, cmap="coolwarm", interpolation="nearest")
    plt.colorbar(label="Correlação de Pearson")
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=45, ha="right")
    plt.yticks(range(len(corr.columns)), corr.columns)
    plt.title("Correlação entre métricas de tráfego")
    plt.tight_layout()
    fname = os.path.join(outdir, f"{timestamp}_correlation.png")
    plt.savefig(fname)
    plt.close()
    print(f"-> Gráfico de correlação salvo em {fname}")

# 2. Entropia de IPs de destino
def plot_entropy(df: pd.DataFrame):
    """
    Calcula e plota a entropia da distribuição de IPs de destino ao longo do tempo.
    Entropia alta -> tráfego diversificado.
    Entropia baixa -> tráfego concentrado em poucos destinos.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = ensure_dir("outputs/statistics")

    if "ip.dst" not in df.columns:
        print("Coluna 'ip.dst' não encontrada. Pulando entropia.")
        return

    df['ts'] = pd.to_datetime(df['frame.time_epoch'], unit='s', errors='coerce')
    df['window'] = df['ts'].dt.floor('5s')

    entropies = []
    for t, group in df.groupby('window'):
        counts = group['ip.dst'].value_counts(normalize=True)
        H = entropy(counts, base=2)
        entropies.append((t, H))

    ent_df = pd.DataFrame(entropies, columns=['window', 'entropy_bits'])

    plt.figure(figsize=(10, 4))
    plt.plot(ent_df['window'], ent_df['entropy_bits'], color='purple')
    plt.title("Entropia de IPs de destino ao longo do tempo")
    plt.xlabel("Tempo (5s)")
    plt.ylabel("Entropia (bits)")
    plt.grid(True)
    plt.tight_layout()

    fname = os.path.join(outdir, f"{timestamp}_entropy.png")
    plt.savefig(fname)
    plt.close()
    print(f"-> Gráfico de entropia salvo em {fname}")

# 3. Distribuição de cauda (heavy-tailed)
def plot_tail_distribution(fe: pd.DataFrame):
    """
    Plota a distribuição log-log (tamanho de pacote x frequência)
    para identificar comportamento heavy-tailed típico de tráfego real.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = ensure_dir("outputs/statistics")

    plt.figure(figsize=(6, 5))
    counts, bins = np.histogram(fe['bytes_total'], bins=50)
    bins = bins[1:]
    plt.loglog(bins, counts + 1, marker='o', linestyle='None')
    plt.title("Distribuição log-log (tamanho x frequência)")
    plt.xlabel("Tamanho total (bytes)")
    plt.ylabel("Frequência (log)")
    plt.grid(True, which="both", ls="--")
    plt.tight_layout()

    fname = os.path.join(outdir, f"{timestamp}_tail.png")
    plt.savefig(fname)
    plt.close()
    print(f"-> Gráfico de cauda salvo em {fname}")

# 4. Função agregadora
def run_statistics(df_raw: pd.DataFrame, fe: pd.DataFrame):
    """
    Executa todas as análises complementares em sequência.
    """
    print("\nExecutando análises estatísticas complementares...")
    plot_correlation(fe)
    plot_entropy(df_raw)
    plot_tail_distribution(fe)
    print("Análises estatísticas finalizadas.\n")
