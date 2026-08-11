import re
import matplotlib.pyplot as plt
from collections import defaultdict
import seaborn as sns
import pandas as pd
import numpy as np

# File path
LOG_FILE = "query_stats.log"
OUTPUT_IMAGE = "query_stats_boxplot.png"

# Regex pattern
pattern = re.compile(r'\[.*?\] RuleID: (.*?) \| Depth: (\d+) \| Node: (.*?) \| Time: (.*)')

def parse_time(time_str):
    time_str = time_str.strip()
    ms = 0.0
    import re as regex
    matches = regex.findall(r'([\d\.]+)(ms|s|µs|us|m|h)', time_str)
    
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
                    
                    # Rút gọn nhãn để đồ thị dễ nhìn
                    short_rule = rule_id.replace("RULE_", "").replace("GENERIC_", "")
                    label = f"[{depth}] {short_rule}\n({node_name})"
                    data.append({"Label": label, "Time (ms)": ms})
    except FileNotFoundError:
        print(f"Error: Could not find {LOG_FILE}")
        return

    if not data:
        print("No valid data found in the log file.")
        return

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # thống kê chi tiết Min/Max/Avg/Std
    print("="*80)
    print(f"{'LUẬT':<80} | {'SỐ LƯỢNG':<10} | {'MIN':<8} | {'MAX':<8} | {'AVG (Mean)':<12} | {'STD'}")
    print("="*80)
    
    stats_df = df.groupby("Label")["Time (ms)"].agg(['count', 'min', 'max', 'mean', 'std']).reset_index()
    stats_df = stats_df.sort_values(by="mean", ascending=False)
    
    for _, row in stats_df.iterrows():
        label_flat = row['Label'].replace('\n', ' ')[:80]
        print(f"{label_flat:<80} | {int(row['count']):<10} | {row['min']:<8.1f} | {row['max']:<8.1f} | {row['mean']:<12.1f} | {row['std']:.2f}")
    
    print("="*80)

    # Plot Box Plot using Seaborn
    # Box plot shows Min, First Quartile, Median, Third Quartile, Max, and Outliers
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(16, 10))
    
    # Chỉ lấy top 15 Node có thời gian trung bình lớn nhất để vẽ (tránh bị rối)
    top_labels = stats_df.head(15)['Label'].tolist()
    plot_df = df[df['Label'].isin(top_labels)]
    
    ax = sns.boxplot(
        x="Time (ms)", 
        y="Label", 
        data=plot_df, 
        order=top_labels,
        palette="vlag",
        showfliers=True # Hiển thị các điểm bất thường (Outliers)
    )
    
    # Thêm chấm đỏ hiển thị giá trị Trung bình (Mean)
    sns.stripplot(
        x="Time (ms)", 
        y="Label", 
        data=plot_df, 
        order=top_labels,
        size=4, color=".3", linewidth=0, alpha=0.5
    )

    plt.title('Phân bố Thời gian Thực thi Cypher theo từng Lớp', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Execution Time (ms)', fontsize=14, fontweight='bold')
    plt.ylabel('Lớp (Depth)', fontsize=14, fontweight='bold')
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=10)

    # Xscale log nếu độ chênh lệch quá lớn (ví dụ có cái 600ms có cái 2ms)
    # plt.xscale("log") # Bỏ comment dòng này nếu bạn muốn xem theo trục Logarit

    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches='tight')
    print(f"✅ {OUTPUT_IMAGE}")

if __name__ == "__main__":
    main()
