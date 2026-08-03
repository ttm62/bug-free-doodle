import re
import matplotlib.pyplot as plt
from collections import defaultdict
import seaborn as sns

# File path
LOG_FILE = "query_stats.log"
OUTPUT_IMAGE = "query_stats_chart.png"

# Regex pattern to parse the log lines
# Example: [2026-08-03T17:44:09+07:00] RuleID: GENERIC_CRYPTOMINER | Depth: 1 | Node: Nhận diện tiến trình đào coin | Time: 326ms
pattern = re.compile(r'\[.*?\] RuleID: (.*?) \| Depth: \d+ \| Node: .*? \| Time: (.*)')

def parse_time(time_str):
    """Converts Go duration string (e.g., '326ms', '1s150ms', '0s') to milliseconds (float)"""
    time_str = time_str.strip()
    ms = 0.0
    
    # Dùng regex để bóc tách từng phần tử (1.5s, 326ms, 5µs)
    import re
    matches = re.findall(r'([\d\.]+)(ms|s|µs|us|m|h)', time_str)
    
    if not matches and time_str.replace('.', '', 1).isdigit(): # Fallback for plain numbers
        return float(time_str)
        
    for val, unit in matches:
        val = float(val)
        if unit == 'ms':
            ms += val
        elif unit == 's':
            ms += val * 1000.0
        elif unit in ('µs', 'us'):
            ms += val / 1000.0
        elif unit == 'm':
            ms += val * 60000.0
        elif unit == 'h':
            ms += val * 3600000.0
            
    return ms

def main():
    rule_times = defaultdict(float)
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    rule_id = match.group(1).strip()
                    time_str = match.group(2).strip()
                    ms = parse_time(time_str)
                    rule_times[rule_id] += ms
    except FileNotFoundError:
        print(f"Error: Could not find {LOG_FILE}")
        return

    if not rule_times:
        print("No valid data found in the log file.")
        return

    # Sort data by execution time (descending)
    sorted_rules = sorted(rule_times.items(), key=lambda x: x[1], reverse=True)
    rules = [x[0] for x in sorted_rules]
    times = [x[1] for x in sorted_rules]

    # Plotting using Seaborn for beautiful aesthetics
    sns.set_theme(style="whitegrid", palette="pastel")
    plt.figure(figsize=(14, 10))
    
    ax = sns.barplot(x=times, y=rules, hue=rules, dodge=False, legend=False, palette="viridis")
    
    # Formatting the chart
    plt.title('Neo4j Cypher Execution Time per Rule (Milliseconds)', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Execution Time (ms)', fontsize=14, fontweight='bold')
    plt.ylabel('Rule ID', fontsize=14, fontweight='bold')
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
    print(f"✅ Đã vẽ xong đồ thị và lưu thành công tại: {OUTPUT_IMAGE}")

if __name__ == "__main__":
    main()
