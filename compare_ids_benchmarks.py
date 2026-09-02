import json
import csv
import argparse
import re
import os
from datetime import datetime, timezone

KEYWORD_MAP = {
    "NETWORK_SCANS": ["quét mạng", "tcp", "nmap", "network", "scan", "port", "flood", "portscan"],
    "SERVICE_SCANS": ["wpcrack", "rà quét web", "service", "wpscan", "http post", "web recon", "dò quét wordpress"],
    "DIRB": ["dirb", "thư mục ẩn", "directory", "dirbuster", "rà quét", "lỗi"],
    "WPSCAN": ["wpcrack", "web diện rộng", "wpscan", "wordpress", "wp-login", "dò quét wordpress"],
    "WEBSHELL": ["webshell", "chèn payload", "upload", "eval", "passthru", "post request", "chèn webshell"],
    "CRACKING": ["dò mật khẩu", "cracking", "băm", "bruteforce", "authentication failed", "failed password", "mật khẩu băm", "shadow"],
    "REVERSE_SHELL": ["shell", "rce", "công cụ quét", "thực thi lệnh", "bash", "/bin/sh", "cmd", "lệnh shell", "reverse shell"],
    "PRIVILEGE_ESCALATION": ["chuyển tài khoản", "sudo", "leo quyền", "leo thang", "su ", "privilege escalation", "root", "ran_as", "su_escalation"],
    "SERVICE_STOP": ["tắt dịch vụ", "evasion", "stop", "disable", "kill", "dịch vụ bảo mật"],
    "DNSTEAL": ["dns", "tunnel", "exfiltration", "dnsteal", "rò rỉ dữ liệu", "tuồn dữ liệu"]
}

def load_ground_truth(labels_file, scenario):
    gt = []
    try:
        with open(labels_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 4 and row[0] == scenario:
                    try:
                        label = row[1]
                        start = float(row[2])
                        end = float(row[3])
                        gt.append({
                            "label": label,
                            "start": start,
                            "end": end,
                            "hit_count": 0,
                            "alerts": []
                        })
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"❌ Không tìm thấy file Ground Truth: {labels_file}")
    return gt

def match_phase(ts, text, gt_stats):
    matched = []
    text_lower = text.lower()
    for gt in gt_stats:
        lbl = gt["label"].upper()
        
        # 1. Kiểm tra thời gian nghiêm ngặt trong khoảng [start, end] của Ground Truth (+- 60s trễ stream)
        in_time_window = (gt["start"] - 60.0 <= ts <= gt["end"] + 60.0)
        
        if in_time_window:
            # 2. Bắt buộc phải khớp ngữ nghĩa từ khóa của đúng phase đó
            semantic_match = False
            if lbl in KEYWORD_MAP:
                for kw in KEYWORD_MAP[lbl]:
                    if kw in text_lower:
                        semantic_match = True
                        break
            else:
                semantic_match = True
            
            if semantic_match:
                gt["hit_count"] += 1
                if text not in gt["alerts"]:
                    gt["alerts"].append(text[:60])
                matched.append(lbl)
    return matched

def eval_aminer(aminer_file, gt_template, dedup_window=0):
    import copy
    gt_stats = copy.deepcopy(gt_template)
    total_alerts = 0
    tp_count = 0
    fp_count = 0
    last_seen = {}

    if not os.path.exists(aminer_file):
        return None

    with open(aminer_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                alert = json.loads(line)
            except:
                continue
            
            # Extract timestamp
            log_data = alert.get("LogData", {})
            timestamps = log_data.get("Timestamps", []) or log_data.get("DetectionTimestamp", [])
            if not timestamps:
                fp_count += 1
                total_alerts += 1
                continue
            ts = float(timestamps[0])

            comp = alert.get("AnalysisComponent", {})
            comp_name = comp.get("AnalysisComponentName", "")
            
            # Deduplication cooldown
            if dedup_window > 0:
                if comp_name in last_seen and (ts - last_seen[comp_name] < dedup_window):
                    continue
                last_seen[comp_name] = ts

            total_alerts += 1

            # Extract message
            msg = comp_name + " " + comp.get("Message", "")
            raw = " ".join(log_data.get("RawLogData", []))
            combined_text = msg + " " + raw

            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    name = f"AMiner (Dedup {dedup_window}s)" if dedup_window > 0 else "AMiner IDS"
    return calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats)

def eval_wazuh(wazuh_file, gt_template, dedup_window=0):
    import copy
    gt_stats = copy.deepcopy(gt_template)
    total_alerts = 0
    tp_count = 0
    fp_count = 0
    last_seen = {}

    if not os.path.exists(wazuh_file):
        return None

    with open(wazuh_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                alert = json.loads(line)
            except:
                continue

            # Chỉ tính các alert có level >= 3
            rule = alert.get("rule", {})
            if rule.get("level", 0) < 3:
                continue

            # Extract timestamp from @timestamp (ISO-8601) or timestamp
            ts_str = alert.get("@timestamp") or alert.get("timestamp")
            ts = None
            if ts_str:
                try:
                    clean_ts = ts_str.replace("+0000", "Z").replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_ts[:19]).replace(tzinfo=timezone.utc)
                    ts = dt.timestamp()
                except:
                    pass

            if not ts:
                total_alerts += 1
                fp_count += 1
                continue

            rule_id = rule.get("id", "")
            # Deduplication cooldown per rule_id
            if dedup_window > 0:
                if rule_id in last_seen and (ts - last_seen[rule_id] < dedup_window):
                    continue
                last_seen[rule_id] = ts

            total_alerts += 1

            desc = rule.get("description", "")
            full_log = alert.get("full_log", "")
            data_obj = alert.get("data", {})
            data_str = json.dumps(data_obj) if data_obj else ""
            combined_text = f"{desc} {full_log} {data_str}"

            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    name = f"Wazuh (Dedup {dedup_window}s)" if dedup_window > 0 else "Wazuh IDS"
    return calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats)

def eval_custom(custom_file, gt_template):
    import copy
    gt_stats = copy.deepcopy(gt_template)
    total_alerts = 0
    tp_count = 0
    fp_count = 0

    if not os.path.exists(custom_file):
        return None

    with open(custom_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                alert = json.loads(line)
            except:
                continue

            total_alerts += 1
            node_name = alert.get("node_name", "")
            alert_msg = alert.get("alert_message", "")
            details = alert.get("details", {})
            
            # Extract time: Ưu tiên mốc thời gian của node hiện tại (time_dns, time_su, time_rce, time_privesc...)
            # Tránh việc lấy nhầm time_wpcrack của tầng L1 khi đang ở tầng L3
            ts = None
            priority_time_keys = [
                "time_dns", "time_dnsteal", "time_sudo", "time_su", "time_privesc", 
                "time_rce", "time_revshell", "time_drop", "time_webshell", 
                "time_recon", "time_wpcrack", "time_cracking", "time_post", "time_service_stop"
            ]
            
            for pk in priority_time_keys:
                if pk in details and isinstance(details[pk], str) and '202' in details[pk]:
                    try:
                        clean_time = details[pk][:19]
                        dt = datetime.strptime(clean_time, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                        ts = dt.timestamp()
                        break
                    except:
                        pass

            if not ts:
                for k, v in details.items():
                    if isinstance(v, str) and '202' in v and 'T' in v:
                        try:
                            clean_time = v[:19]
                            dt = datetime.strptime(clean_time, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                            ts = dt.timestamp()
                            break
                        except:
                            pass

            if not ts:
                match = re.search(r'(202\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', alert_msg)
                if match:
                    try:
                        dt = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                        ts = dt.timestamp()
                    except:
                        pass

            if not ts:
                fp_count += 1
                continue

            rule_name = alert.get("rule_name", "")
            combined_text = f"{rule_name} {node_name} {alert_msg}"
            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    return calc_metrics("Custom Engine (Graph + Tree)", total_alerts, tp_count, fp_count, gt_stats)

def calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats):
    total_phases = len(gt_stats)
    detected_phases = sum(1 for gt in gt_stats if gt["hit_count"] > 0)
    
    precision = (tp_count / total_alerts * 100) if total_alerts > 0 else 0
    recall = (detected_phases / total_phases * 100) if total_phases > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    return {
        "name": name,
        "total_alerts": total_alerts,
        "tp": tp_count,
        "fp": fp_count,
        "detected_phases": detected_phases,
        "total_phases": total_phases,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "gt_stats": gt_stats
    }

def print_comparison_table(results, scenario):
    print("\n" + "="*85)
    print(f"📊 BẢNG SO SÁNH HIỆU NĂNG PHÁT HIỆN TẤN CÔNG (Kịch bản: {scenario.upper()})")
    print("="*85)
    
    header = f"{'Chỉ số Đánh giá':<32} | " + " | ".join([f"{r['name']:<24}" for r in results])
    print(header)
    print("-" * len(header))
    
    row_total = f"{'Tổng số Alert sinh ra':<32} | " + " | ".join([f"{r['total_alerts']:<24,}" for r in results])
    row_tp = f"{'True Positives (TP - Chuẩn)':<32} | " + " | ".join([f"{r['tp']:<24,}" for r in results])
    row_fp = f"{'False Positives (FP - Nhiễu)':<32} | " + " | ".join([f"{r['fp']:<24,}" for r in results])
    row_phases = f"{'Số Giai đoạn phát hiện':<32} | " + " | ".join([f"{r['detected_phases']}/{r['total_phases']} ({r['recall']:.1f}%)".ljust(24) for r in results])
    row_prec = f"{'Precision (Độ chuẩn xác)':<32} | " + " | ".join([f"{r['precision']:.2f}%".ljust(24) for r in results])
    row_rec = f"{'Recall / Phase Coverage':<32} | " + " | ".join([f"{r['recall']:.2f}%".ljust(24) for r in results])
    row_f1 = f"{'F1-Score':<32} | " + " | ".join([f"{r['f1']:.2f}%".ljust(24) for r in results])
    
    print(row_total)
    print(row_tp)
    print(row_fp)
    print(row_phases)
    print(row_prec)
    print(row_rec)
    print(row_f1)
    print("="*85)

    print("\n📋 CHI TIẾT ĐỘ PHỦ TỪNG GIAI ĐOẠN (ATTACK PHASES):")
    total_phases = results[0]["total_phases"]
    for i in range(total_phases):
        lbl = results[0]["gt_stats"][i]["label"]
        start_h = datetime.fromtimestamp(results[0]["gt_stats"][i]["start"], tz=timezone.utc).strftime('%H:%M')
        end_h = datetime.fromtimestamp(results[0]["gt_stats"][i]["end"], tz=timezone.utc).strftime('%H:%M')
        
        status_cols = []
        for r in results:
            hit = r["gt_stats"][i]["hit_count"]
            status = f"✅ ({hit:3d})" if hit > 0 else "❌ (  0)"
            status_cols.append(f"{status:<24}")
            
        print(f"  [{i+1}/{total_phases}] {lbl.upper():<22} ({start_h}->{end_h}) | " + " | ".join(status_cols))
    print("="*85 + "\n")

def main():
    parser = argparse.ArgumentParser(description="So sánh hiệu năng IDS: AMiner vs Wazuh vs Custom Engine")
    parser.add_argument("--scenario", default="russellmitchell", help="Tên kịch bản (russellmitchell, fox, santos, wardbeck)")
    parser.add_argument("--labels", default="ait_ads/labels.csv", help="File labels.csv")
    parser.add_argument("--aminer", default=None, help="File aminer json")
    parser.add_argument("--wazuh", default=None, help="File wazuh json")
    parser.add_argument("--custom", default="detection_alerts.jsonl", help="File alerts của Custom Engine")
    parser.add_argument("--dedup-window", type=float, default=0.0, help="Cửa sổ thời gian khử trùng lặp (giây) cho AMiner và Wazuh (VD: 5.0)")
    
    args = parser.parse_args()

    aminer_path = args.aminer or f"ait_ads/{args.scenario}_aminer.json"
    wazuh_path = args.wazuh or f"ait_ads/{args.scenario}_wazuh.json"
    custom_path = args.custom

    gt_template = load_ground_truth(args.labels, args.scenario)
    if not gt_template:
        return

    results = []
    
    # 1. Evaluate AMiner
    r_aminer = eval_aminer(aminer_path, gt_template, dedup_window=args.dedup_window)
    if r_aminer: results.append(r_aminer)

    # 2. Evaluate Wazuh
    r_wazuh = eval_wazuh(wazuh_path, gt_template, dedup_window=args.dedup_window)
    if r_wazuh: results.append(r_wazuh)

    # 3. Evaluate Custom
    r_custom = eval_custom(custom_path, gt_template)
    if r_custom: results.append(r_custom)

    if results:
        print_comparison_table(results, args.scenario)

if __name__ == "__main__":
    main()
