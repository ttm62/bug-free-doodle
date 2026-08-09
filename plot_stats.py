import re
import matplotlib.pyplot as plt
from collections import defaultdict
import seaborn as sns
import statistics

# File path
LOG_FILE = "query_stats.log"
OUTPUT_IMAGE = "query_stats_chart.png"

# Regex pattern to parse the log lines
# Example: [2026-08-03T17:44:09+07:00] RuleID: GENERIC_CRYPTOMINER | Depth: 1 | Node: Nhận diện tiến trình đào coin | Time: 326ms
pattern = re.compile(r'\[.*?\] RuleID: (.*?) \| Depth: (\d+) \| Node: (.*?) \| Time: (.*)')

def parse_time(time_str):
    """Converts Go duration string to milliseconds (float)"""
    time_str = time_str.strip()
    ms = 0.0
    import re as regex
    matches = regex.findall(r'([\d\.]+)(ms|s|µs|us|m|h)', time_str)
    
    if not matches and time_str.replace('.', '', 1).isdigit(): # Fallback
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
    # Store all execution times for each Rule-Node combination
    node_times = defaultdict(list)
    
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
                    
                    # Create a descriptive label combining Rule, Depth, and Node
                    label = f"{rule_id}\n(Lớp {depth}: {node_name})"
                    node_times[label].append(ms)
    except FileNotFoundError:
        print(f"Error: Could not find {LOG_FILE}")
        return

    if not node_times:
        print("No valid data found in the log file.")
        return

    # Calculate AVERAGE time for each node
    avg_times = []
    for label, times in node_times.items():
        avg = statistics.mean(times)
        avg_times.append((label, avg))

    # Sort data by average execution time (descending)
    sorted_nodes = sorted(avg_times, key=lambda x: x[1], reverse=True)
    
    # Extract top 15 heaviest queries to fit the chart nicely
    top_nodes = sorted_nodes[:15]
    
    labels = [x[0] for x in top_nodes]
    times = [x[1] for x in top_nodes]

    # Plotting using Seaborn
    sns.set_theme(style="whitegrid", palette="pastel")
    plt.figure(figsize=(14, 12)) # Taller for multiline labels
    
    ax = sns.barplot(x=times, y=labels, hue=labels, dodge=False, legend=False, palette="viridis")
    
    # Formatting the chart
    plt.title('Neo4j Average Execution Time per Layer', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Average Execution Time (ms)', fontsize=14, fontweight='bold')
    plt.ylabel('Rule ID & Detection Node', fontsize=14, fontweight='bold')
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=11)

    # Add value labels to bars
    for i, p in enumerate(ax.patches):
        width = p.get_width()
        plt.text(width + max(times)*0.01, p.get_y() + p.get_height()/2. + 0.1, 
                 '{:1.1f} ms'.format(width), 
                 ha="left", va="center", fontsize=10, color='black', fontweight='bold')

    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches='tight')
    print(f"✅ Đã vẽ xong đồ thị trung bình theo từng Lớp và lưu tại: {OUTPUT_IMAGE}")

if __name__ == "__main__":
    main()
