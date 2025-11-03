#!/usr/bin/env python3
"""
Análise estatística de tráfego de rede
--------------------------------------
Lê um CSV de pacotes reais (Wireshark/tshark) ou sintéticos,
agrega métricas por janelas temporais e aplica múltiplas
abordagens estatísticas (rolling, global) com z-score robusto e CUSUM.

Uso:
    python src/detect/anomaly.py --in data/raw/flows.csv --out outputs/alerts.csv
"""

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pandas as pd
import numpy as np
import argparse
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
from src.analysis.statistics_analysis import run_statistics


# Funções utilitárias

def robust_z(x: pd.Series, win: int = 20) -> pd.Series:
    """Z-score robusto baseado em mediana e MAD."""
    med = x.rolling(win, min_periods=win // 3).median()
    mad = (x - med).abs().rolling(win, min_periods=win // 3).median()
    z = (x - med) / (1.4826 * mad.replace(0, np.nan))
    return z.fillna(0).clip(-8, 8)

def cusum(x: np.ndarray, k: float = 0.5, h: float = 5) -> np.ndarray:
    """CUSUM bilateral simples."""
    s_pos = np.zeros_like(x)
    s_neg = np.zeros_like(x)
    out = np.zeros_like(x)
    for i in range(1, len(x)):
        s_pos[i] = max(0, s_pos[i-1] + x[i] - k)
        s_neg[i] = min(0, s_neg[i-1] + x[i] + k)
        out[i] = max(s_pos[i], -s_neg[i])
    return out

def top_features(row, feature_cols, n=2):
    """Seleciona as n features com maior |z|."""
    vals = row[feature_cols].abs().sort_values(ascending=False).head(n)
    return ','.join(f'{k}:{row[k]:.1f}' for k in vals.index)

# Função auxiliar: múltiplas análises

def run_analysis_versions(fe, feature_cols):
    """
    Gera múltiplas versões do gráfico de anomalias comparando métodos estatísticos.
    """
    os.makedirs("outputs/comparisons", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    configs = [
        {"label": "rolling60", "win": 60, "desc": "Rolling window padrão (60)"},
        {"label": "rolling20", "win": 20, "desc": "Rolling window curta (20)"},
        {"label": "global", "win": None, "desc": "Média global (não adaptativa)"}
    ]

    results = []

    for cfg in configs:
        fe_copy = fe.copy()

        if cfg["win"] is None:
            # --- Média global (sem janela deslizante) ---
            for col in ['bytes_total','pkts_total','uniq_dst_ports','flows_total','mean_iat_ms']:
                med = fe_copy[col].median()
                mad = (fe_copy[col] - med).abs().median()
                z = (fe_copy[col] - med) / (1.4826 * mad)
                fe_copy[f'z_{col}'] = z.clip(-8, 8)
        else:
            # --- Rolling robusto ---
            for col in ['bytes_total','pkts_total','uniq_dst_ports','flows_total','mean_iat_ms']:
                fe_copy[f'z_{col}'] = robust_z(fe_copy[col], win=cfg["win"])

        # --- Cálculo principal ---
        fe_copy['z_mean'] = fe_copy[[f'z_{c}' for c in feature_cols]].abs().mean(axis=1)
        fe_copy['cusum'] = cusum(fe_copy['z_mean'].values, k=0.5, h=5)

        # --- Plot ---
        plt.figure(figsize=(10, 4))
        plt.plot(fe_copy['window'], fe_copy['z_mean'], label='z_mean')
        plt.plot(fe_copy['window'], fe_copy['cusum'], label='CUSUM', linestyle='--')
        plt.legend()
        start, end = fe_copy['window'].min(), fe_copy['window'].max()
        plt.title(f"{cfg['desc']}  ({start:%H:%M:%S} -> {end:%H:%M:%S})")
        plt.xlabel("Tempo (janelas de 5s)")
        plt.ylabel("|z| médio / CUSUM")
        plt.grid(True)
        plt.tight_layout()

        fname = f"outputs/comparisons/{timestamp}_{cfg['label']}.png"
        plt.savefig(fname)
        plt.close()
        print(f"-> Gráfico salvo em {fname}")
        results.append(fname)

    return results

# Pipeline principal

def detect_anomalies(input_csv: Path, output_csv: Path):
    print(f"Lendo dados de {input_csv} ...")
    df = pd.read_csv(input_csv)

    # --- Ajuste automático (funciona para tshark ou sintético) ---
    if 'frame.time_epoch' in df.columns:
        df['ts'] = pd.to_datetime(df['frame.time_epoch'], unit='s', errors='coerce')
        df['ts'] = df['ts'].dt.tz_localize('UTC').dt.tz_convert('America/Recife')
        df['dst_port'] = df[['tcp.dstport', 'udp.dstport']].fillna(0).max(axis=1)
        df = df.dropna(subset=['ts'])
        df['window'] = df['ts'].dt.floor('5s')
        g = df.groupby('window')
        fe = pd.DataFrame({
            'bytes_total': g['frame.len'].sum(),
            'pkts_total': g['frame.len'].count(),
            'uniq_dst_ports': g['dst_port'].nunique(),
            'flows_total': g.size(),
            'mean_iat_ms': g['ts'].apply(lambda s: s.sort_values().diff().dt.total_seconds().dropna().mean() * 1000)
        }).fillna(0.0).reset_index()
    else:
        df['window'] = pd.to_datetime(df['epoch'], unit='s').dt.floor('5s')
        fe = df.groupby('window')['bytes'].sum().reset_index().rename(columns={'bytes': 'bytes_total'})
        fe['pkts_total'] = fe['bytes_total'] / 500
        fe['uniq_dst_ports'] = 1
        fe['flows_total'] = fe['bytes_total'] // 1000
        fe['mean_iat_ms'] = 100

    # --- Estatísticas padrão ---
    feature_cols = ['bytes_total','pkts_total','uniq_dst_ports','flows_total','mean_iat_ms']
    for col in feature_cols:
        fe[f'z_{col}'] = robust_z(fe[col], win=20)

    fe['z_mean'] = fe[[f'z_{c}' for c in feature_cols]].abs().mean(axis=1)
    fe['cusum'] = cusum(fe['z_mean'].values, k=0.5, h=5)
    fe['alarm'] = (fe['z_mean'] >= 2.5) | (fe['cusum'] >= 4)
    fe['why'] = fe.apply(top_features, axis=1, feature_cols=[f'z_{c}' for c in feature_cols])

    alerts = fe.loc[fe['alarm'], ['window','z_mean','cusum','why']]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(output_csv, index=False)
    print(f"{len(alerts)} anomalias detectadas. Resultados em {output_csv}")

    print(f"Média bytes_total: {fe['bytes_total'].mean():.1f}")
    print(f"Máximo bytes_total: {fe['bytes_total'].max():.1f}")
    print(f"Desvio padrão bytes_total: {fe['bytes_total'].std():.1f}")

    # --- Gráfico principal (baseline) ---
    try:
        plt.figure(figsize=(10, 4))
        plt.plot(fe['window'], fe['z_mean'], label='|z| médio')
        plt.plot(fe['window'], fe['cusum'], label='CUSUM', linestyle='--')
        plt.legend()
        start, end = fe['window'].min(), fe['window'].max()
        plt.title(f"Detecção estatística de anomalias ({start:%H:%M:%S} -> {end:%H:%M:%S})")
        plt.tight_layout()
        plt.savefig(output_csv.with_suffix('.png'))
        print("Gráfico principal salvo em", output_csv.with_suffix('.png'))
    except Exception as e:
        print("Plot opcional falhou:", e)

    # --- Rodar múltiplas análises comparativas ---
    print("\nExecutando análises comparativas (win=60, win=20, global)...")
    run_analysis_versions(fe, feature_cols)

    # --- Rodar análises estatísticas complementares ---
    run_statistics(df, fe)

# CLI

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detecção estatística de anomalias em tráfego de rede")
    parser.add_argument("--in", dest="input_csv", required=True, help="CSV de entrada (tshark ou sintético)")
    parser.add_argument("--out", dest="output_csv", required=True, help="Arquivo de saída (alerts.csv)")
    args = parser.parse_args()

    detect_anomalies(Path(args.input_csv), Path(args.output_csv))
