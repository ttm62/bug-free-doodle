import json
import csv
import argparse
import re
from datetime import datetime, timezone

def main():
    parser = argparse.ArgumentParser(description="Đánh giá chi tiết thời gian phát hiện so với Ground Truth")
    parser.add_argument("alerts_file", help="File chứa các cảnh báo JSONL (VD: detection_alerts.jsonl)")
    parser.add_argument("labels_file", help="File CSV chứa Ground Truth (VD: ait_ads/labels.csv)")
    parser.add_argument("scenario", help="Tên kịch bản tấn công (VD: russellmitchell, fox)")
    
    args = parser.parse_args()
    
    # Load ground truth
    ground_truth = []
    try:
        with open(args.labels_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 4 and row[0] == args.scenario:
                    try:
                        label = row[1]
                        start = float(row[2])
                        end = float(row[3])
                        ground_truth.append((label, start, end))
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"❌ Không tìm thấy file {args.labels_file}")
        return
                
    if not ground_truth:
        print(f"⚠️ Cảnh báo: Không tìm thấy dữ liệu Ground Truth nào cho kịch bản '{args.scenario}'")
        return
        
    gt_stats = []
    for label, start, end in ground_truth:
        gt_stats.append({
            "label": label,
            "start": start,
            "end": end,
            "hit_count": 0,
            "alerts": []
        })

    keyword_map = {
        "NETWORK_SCANS": ["quét mạng", "tcp", "nmap", "network"],
        "SERVICE_SCANS": ["wpcrack", "rà quét web", "service"],
        "DIRB": ["dirb", "thư mục ẩn"],
        "WPSCAN": ["wpcrack", "web diện rộng", "wpscan"],
        "WEBSHELL": ["webshell", "chèn payload"],
        "CRACKING": ["dò mật khẩu", "cracking", "băm"],
        "REVERSE_SHELL": ["shell", "rce", "công cụ quét", "thực thi lệnh"],
        "PRIVILEGE_ESCALATION": ["chuyển tài khoản", "sudo", "leo quyền", "su "],
        "SERVICE_STOP": ["tắt dịch vụ", "evasion", "stop"],
        "DNSTEAL": ["dns"]
    }

    def get_labels_and_record(ts, node_name):
        matched = []
        name_lower = node_name.lower()
        
        for gt in gt_stats:
            lbl = gt["label"].upper()
            
            # Check Time Match (Strict)
            time_match = (gt["start"] <= ts <= gt["end"])
            
            # Check Semantic Match with Time Drift
            # Chỉ chấp nhận Semantic nếu sai số thời gian không quá 1 giờ
            time_drift_allowed = (gt["start"] - 3600 <= ts <= gt["end"] + 3600)
            
            semantic_match = False
            if time_drift_allowed and lbl in keyword_map:
                for kw in keyword_map[lbl]:
                    if kw.lower() in name_lower:
                        semantic_match = True
                        break
                        
            if time_match or semantic_match:
                gt["hit_count"] += 1
                match_type = "TEXT" if not time_match else ("TIME+TEXT" if semantic_match else "TIME")
                
                if node_name not in gt["alerts"]:
                    gt["alerts"].append(node_name)
                    
                matched.append((gt["label"], gt["start"], gt["end"], match_type))
                
        return matched

    def extract_real_time(alert):
        details = alert.get('details', {})
        
        for k, v in details.items():
            if isinstance(v, str) and '202' in v and 'T' in v:
                return v
                
        msg = alert.get('alert_message', '')
        match = re.search(r'(202\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)', msg)
        if match:
            return match.group(1)
            
        return None
        
    print(f"--- CHI TIẾT THỜI GIAN PHÁT HIỆN: '{args.alerts_file}' (Kịch bản: '{args.scenario}') ---")
    
    try:
        with open(args.alerts_file, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    alert = json.loads(line)
                except:
                    continue
                    
                node_name = alert.get('node_name', 'Unknown')
                
                time_str = extract_real_time(alert)
                
                if time_str:
                    try:
                        clean_time = time_str[:19]
                        dt = datetime.strptime(clean_time, "%Y-%m-%dT%H:%M:%S")
                        dt = dt.replace(tzinfo=timezone.utc)
                        ts = dt.timestamp()
                        
                        matches = get_labels_and_record(ts, node_name)
                        time_human = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                        
                        if matches:
                            for label, start, end, match_type in matches:
                                start_human = datetime.fromtimestamp(start, tz=timezone.utc).strftime('%H:%M:%S')
                                end_human = datetime.fromtimestamp(end, tz=timezone.utc).strftime('%H:%M:%S')
                                print(f"[HIT - {label.upper()}] [{match_type}] Alert: {node_name}")
                                print(f"  - Event Time: {time_human} (Epoch: {ts})")
                                print(f"  - Ground Truth: {start_human} -> {end_human}")
                                print("-" * 60)
                        else:
                            print(f"[OUT_OF_WINDOW] Alert: {node_name}")
                            print(f"  - Event Time: {time_human} (Epoch: {ts})")
                            print(f"  - Status: Does not match any ground truth phase")
                            print("-" * 60)
                            
                    except Exception as e:
                        pass
                else:
                    print(f"[SKIPPED] Alert: {node_name}")
                    print(f"  - Reason: No valid 2022 timestamp found to map with Ground Truth.")
                    print("-" * 60)
                    
        print("\n" + "="*60)
        print(f"GROUND TRUTH COVERAGE SUMMARY (Scenario: {args.scenario})")
        print("="*60)
        
        total_phases = len(gt_stats)
        detected_phases = sum(1 for gt in gt_stats if gt["hit_count"] > 0)
        
        if total_phases > 0:
            for i, gt in enumerate(gt_stats):
                start_h = datetime.fromtimestamp(gt["start"], tz=timezone.utc).strftime('%H:%M:%S')
                end_h = datetime.fromtimestamp(gt["end"], tz=timezone.utc).strftime('%H:%M:%S')
                
                status = "DETECTED" if gt["hit_count"] > 0 else "MISSED  "
                print(f"[{i+1}/{total_phases}] {status} | Phase: {gt['label'].upper()} ({start_h} -> {end_h})")
                if gt["hit_count"] > 0:
                    print(f"       Alerts matched: {gt['hit_count']}")
                    print(f"       Alert names: {', '.join(gt['alerts'])}")
            
            print("-" * 60)
            print(f"TOTAL COVERAGE: {detected_phases}/{total_phases} phases detected ({(detected_phases/total_phases*100):.1f}%)\n")
    except FileNotFoundError:
        print(f"Error: File {args.alerts_file} not found")

if __name__ == "__main__":
    main()
