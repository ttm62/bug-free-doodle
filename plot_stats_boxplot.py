import re
import matplotlib.pyplot as plt
from collections import defaultdict
import seaborn as sns
import pandas as pd
import numpy as np
from matplotlib.lines import Line2D

LOG_FILE = "query_stats.log"
OUTPUT_IMAGE = "query_stats_boxplot.png"

pattern = re.compile(r'\[.*?\] RuleID: (.*?) \| Depth: (\d+) \| Node: (.*?) \| Time: (.*)')

def parse_time(time_str):
    time_str = time_str.strip()
    ms = 0.0
    matches = re.findall(r'([\d\.]+)(ms|s|µs|us|m|h)', time_str)
    
    if not matches and time_str.replace('.', '', 1).isdigit():
        return float(time_str)
        
    for val, unit in matches:
        val = float(val)
        if unit == 'ms': ms += val
        elif unit == 's': ms += val * 1000.0
        elif unit in ('µs', 'us'): ms += val / 1000.0
        elif unit == 'm': ms += val * 60000.0
        elif unit == 'h': ms += val * 3600000.0
    return ms

def main():
    data = []
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    rule_id = match.group(1).strip()
                    depth = match.group(2).strip()
                    node_name = match.group(3).strip()
                    time_str = match.group(4).strip()
                    ms = parse_time(time_str)
                    
                    short_rule = rule_id.replace("RULE_", "").replace("GENERIC_", "")
                    label = f"[{depth}] {short_rule}\n({node_name})"
                    data.append({"Label": label, "Time (ms)": ms})
    except FileNotFoundError:
        print(f"Error: Could not find {LOG_FILE}")
        return

    if not data:
        print("No valid data found in the log file.")
        return

    df = pd.DataFrame(data)

    print("="*90)
    print(f"{'LUẬT / NODE':<48} | {'COUNT':<8} | {'MIN':<8} | {'MEDIAN':<8} | {'AVG':<8} | {'MAX':<8} | {'STD'}")
    print("="*90)
    
    stats_df = df.groupby("Label")["Time (ms)"].agg(
        count='count',
        min='min',
        max='max',
        mean='mean',
        median='median',
        std='std'
    ).reset_index()
    stats_df = stats_df.sort_values(by="mean", ascending=False)
    
    for _, row in stats_df.iterrows():
        label_flat = row['Label'].replace('\n', ' - ')[:46]
        std_val = 0.0 if pd.isna(row['std']) else row['std']
        print(f"{label_flat:<48} | {int(row['count']):<8} | {row['min']:<8.1f} | {row['median']:<8.1f} | {row['mean']:<8.1f} | {row['max']:<8.1f} | {std_val:.2f}")
    
    print("="*90)

    sns.set_theme(style="white", palette="muted")
    plt.rcParams.update({
        'font.sans-serif': ['Segoe UI', 'DejaVu Sans', 'Arial', 'Helvetica'],
        'axes.edgecolor': '#cccccc',
        'axes.linewidth': 0.8,
        'grid.color': '#ebebeb',
        'grid.linestyle': '--',
        'grid.alpha': 0.7
    })

    num_items = min(15, len(stats_df))
    top_labels = stats_df.head(num_items)['Label'].tolist()
    plot_df = df[df['Label'].isin(top_labels)].copy()

    fig, ax = plt.subplots(figsize=(15, max(8, num_items * 0.65)), dpi=300)
    colors = sns.color_palette("mako_r", n_colors=num_items)

    sns.boxplot(
        x="Time (ms)", 
        y="Label", 
        data=plot_df, 
        order=top_labels,
        palette=colors,
        width=0.6,
        linewidth=1.3,
        fliersize=3.0,
        flierprops=dict(marker='o', markerfacecolor='#e74c3c', markeredgecolor='none', alpha=0.3),
        boxprops=dict(alpha=0.9, edgecolor='#2d3748'),
        medianprops=dict(color='#ffffff', linewidth=2.2),
        whiskerprops=dict(color='#2d3748', linewidth=1.3),
        capprops=dict(color='#2d3748', linewidth=1.3),
        showmeans=True,
        meanprops=dict(marker='D', markeredgecolor='#ffffff', markerfacecolor='#e67e22', markersize=6.5),
        ax=ax
    )

    for i, label in enumerate(top_labels):
        row_stat = stats_df[stats_df['Label'] == label].iloc[0]
        mean_val = row_stat['mean']
        median_val = row_stat['median']
        ax.text(
            ax.get_xlim()[1] * 0.98 if ax.get_xscale() != 'log' else ax.get_xlim()[1] * 0.8,
            i,
            f" Avg: {mean_val:.1f}ms  |  Med (Q2): {median_val:.1f}ms",
            va='center',
            ha='right',
            fontsize=9.5,
            fontweight='semibold',
            color='#2d3748',
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#f8fafc', edgecolor='#cbd5e1', alpha=0.95)
        )

    ax.set_title("Phân Bố Tứ Phân Vị (IQR) & Hiệu Năng Thực Thi Truy Vấn Cypher", 
                 fontsize=15, fontweight='bold', pad=18, color='#1a202c')
    ax.set_xlabel("Thời Gian Thực Thi (Execution Time - ms)", fontsize=12, fontweight='bold', labelpad=10, color='#2d3748')
    ax.set_ylabel("Cấp Độ & Quy Tắc Phát Hiện (Depth & Node)", fontsize=12, fontweight='bold', labelpad=10, color='#2d3748')

    ax.grid(True, axis='x', linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    sns.despine(top=True, right=True, left=False, bottom=False)

    legend_elements = [
        Line2D([0], [0], color='#ffffff', lw=2.5, label='Trung vị / Q2 (Median)'),
        Line2D([0], [0], marker='D', color='w', markerfacecolor='#e67e22', markeredgecolor='#ffffff', markersize=7, label='Trung bình (Mean)'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#e74c3c', markersize=5, label='Ngoại lệ (Outlier)')
    ]
    ax.legend(handles=legend_elements, loc='lower right', frameon=True, facecolor='white', framealpha=0.9, edgecolor='#cbd5e0', fontsize=9.5)

    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches='tight')
    print(f"✅ {OUTPUT_IMAGE}")

if __name__ == "__main__":
    main()
