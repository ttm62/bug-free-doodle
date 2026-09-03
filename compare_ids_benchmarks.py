import json
import csv
import argparse
import re
import os
import copy
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

def extract_entity(data, fallback_text=""):
    if isinstance(data, dict):
        for key in ("attacker_ip", "exfil_ip", "srcip", "src_ip", "source_ip", "ip", "user", "username", "compromised_user", "agent_id", "id"):
            value = data.get(key)
            if value not in (None, ""):
                return str(value)

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", fallback_text)
    return match.group(0) if match else "unknown"

def is_duplicate(last_seen, dedup_key, ts, dedup_window):
    if dedup_window <= 0:
        return False

    previous = last_seen.get(dedup_key)
    if previous is not None:
        delta = ts - previous
        if 0 <= delta < dedup_window:
            return True

    if previous is None or ts > previous:
        last_seen[dedup_key] = ts
    return False

def extract_custom_attack_time(details, alert_message):
    priority_time_keys = [
        "time_dns", "time_dnsteal", "time_sudo", "time_su", "time_privesc",
        "time_rce", "time_revshell", "time_drop", "time_webshell",
        "time_recon", "time_wpcrack", "time_cracking", "time_post", "time_service_stop",
    ]

    def parse_time(value):
        if not isinstance(value, str) or "T" not in value:
            return None
        try:
            return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None

    for key in priority_time_keys:
        attack_time = parse_time(details.get(key))
        if attack_time is not None:
            return attack_time

    for value in details.values():
        attack_time = parse_time(value)
        if attack_time is not None:
            return attack_time

    match = re.search(r'(202\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', alert_message)
    return parse_time(match.group(1)) if match else None

def load_ground_truth_from_attacktimes(attacktimes_file, scenario):
    gt = []
    if not os.path.exists(attacktimes_file):
        return None
    try:
        with open(attacktimes_file, "r", encoding="utf-8") as f:
            content = f.read()

        pattern = rf"[\'\"]{scenario}[\'\"]\s*:\s*\{{([^}}]+)\}}"
        sc_match = re.search(pattern, content)
        if not sc_match:
            return None

        body = sc_match.group(1)
        phase_pattern = r"[\'\"]([a-zA-Z0-9_-]+)[\'\"]\s*:\s*\[datetime\.strptime\([\'\"]([^\'\"]+)[\'\"],[^,]+,\s*datetime\.strptime\([\'\"]([^\'\"]+)[\'\"]"
        
        for p_match in re.finditer(phase_pattern, body):
            label = p_match.group(1)
            if label.startswith("false_positive"):
                continue
            start_str = p_match.group(2)
            end_str = p_match.group(3)
            try:
                start_ts = datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                end_ts = datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                gt.append({
                    "label": label,
                    "start": start_ts,
                    "end": end_ts,
                    "hit_count": 0,
                    "alerts": []
                })
            except ValueError:
                pass
    except Exception as e:
        print(f"⚠️ Lỗi khi parse {attacktimes_file}: {e}")
        return None
    return gt if gt else None

def load_ground_truth(labels_file, scenario, attacktimes_file="alert-data-set-main/attacktimes.py"):
    # Nếu người dùng truyền một file nhãn tùy chỉnh (ví dụ labels2.csv), ưu tiên đọc trực tiếp từ file đó
    if labels_file and labels_file != "ait_ads/labels.csv" and os.path.exists(labels_file):
        pass
    elif attacktimes_file and os.path.exists(attacktimes_file):
        gt = load_ground_truth_from_attacktimes(attacktimes_file, scenario)
        if gt:
            return gt

    gt = []
    try:
        with open(labels_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 4 and row[0] == scenario:
                    try:
                        label = row[1]
                        if label.startswith("false_positive"):
                            continue
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
        
        in_time_window = (gt["start"] - 60.0 <= ts <= gt["end"] + 60.0)
        
        if in_time_window:
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
            
            log_data = alert.get("LogData", {})
            timestamps = log_data.get("Timestamps", []) or log_data.get("DetectionTimestamp", [])
            if not timestamps:
                fp_count += 1
                total_alerts += 1
                continue
            ts = float(timestamps[0])

            comp = alert.get("AnalysisComponent", {})
            comp_name = comp.get("AnalysisComponentName", "")
            
            msg = comp_name + " " + comp.get("Message", "")
            raw = " ".join(log_data.get("RawLogData", []))
            combined_text = msg + " " + raw

            sensor = alert.get("AMiner", {}).get("ID", "unknown")
            entity = f"{sensor}|{extract_entity({}, raw)}"
            dedup_key = (comp_name, entity)
            if is_duplicate(last_seen, dedup_key, ts, dedup_window):
                continue

            total_alerts += 1

            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    name = f"AMiner (Dedup {dedup_window}s)" if dedup_window > 0 else "AMiner IDS"
    return calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats)

def eval_wazuh(wazuh_file, gt_template, dedup_window=0):
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

            rule = alert.get("rule", {})
            if rule.get("level", 0) < 3:
                continue

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

            desc = rule.get("description", "")
            full_log = alert.get("full_log", "")
            data_obj = alert.get("data", {})
            data_str = json.dumps(data_obj) if data_obj else ""
            combined_text = f"{desc} {full_log} {data_str}"

            rule_id = rule.get("id", "")
            entity = extract_entity(data_obj, combined_text)
            dedup_key = (rule_id, entity)
            if is_duplicate(last_seen, dedup_key, ts, dedup_window):
                continue

            total_alerts += 1

            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    name = f"Wazuh (Dedup {dedup_window}s)" if dedup_window > 0 else "Wazuh IDS"
    return calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats)

def eval_labeled_siem(alerts_csv_file, siem_name, gt_template, dedup_window=0):
    gt_stats = copy.deepcopy(gt_template)
    phase_stats = {gt["label"].lower(): gt for gt in gt_stats}
    total_alerts = 0
    tp_count = 0
    fp_count = 0
    last_seen = {}

    with open(alerts_csv_file, "r", newline="") as f:
        for row in csv.DictReader(f):
            if not row.get("name", "").startswith(f"{siem_name}:"):
                continue

            try:
                ts = float(row["time"])
            except (KeyError, TypeError, ValueError):
                total_alerts += 1
                fp_count += 1
                continue

            dedup_key = (row.get("short") or row.get("name", ""), row.get("ip", ""), row.get("host", ""))
            if is_duplicate(last_seen, dedup_key, ts, dedup_window):
                continue

            total_alerts += 1
            phase = row.get("time_label", "").strip().lower()
            if phase in phase_stats:
                tp_count += 1
                phase_stats[phase]["hit_count"] += 1
            else:
                fp_count += 1

    suffix = f", Dedup {dedup_window}s" if dedup_window > 0 else ""
    return calc_metrics(f"{siem_name} (Label CSV{suffix})", total_alerts, tp_count, fp_count, gt_stats)

def eval_custom(custom_file, gt_template, dedup_window=0):
    gt_stats = copy.deepcopy(gt_template)
    total_alerts = 0
    tp_count = 0
    fp_count = 0
    last_seen = {}

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

            node_name = alert.get("node_name", "")
            alert_msg = alert.get("alert_message", "")
            details = alert.get("details", {})
            
            ts = extract_custom_attack_time(details, alert_msg)

            if not ts:
                total_alerts += 1
                fp_count += 1
                continue

            rule_name = alert.get("rule_name", "")
            combined_text = f"{rule_name} {node_name} {alert_msg}"
            rule_id = alert.get("rule_id", "")
            node_id = alert.get("node_id", "")
            entity = extract_entity(details, combined_text)
            dedup_key = (rule_id, node_id, entity)
            if is_duplicate(last_seen, dedup_key, ts, dedup_window):
                continue

            total_alerts += 1
            matched = match_phase(ts, combined_text, gt_stats)
            if matched:
                tp_count += 1
            else:
                fp_count += 1

    name = f"Custom Engine (Dedup {dedup_window}s)" if dedup_window > 0 else "Custom Engine"
    return calc_metrics(name, total_alerts, tp_count, fp_count, gt_stats)

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
    print(f"BẢNG HIỆU NĂNG PHÁT HIỆN TẤN CÔNG ({scenario.upper()})")
    print("="*85)

    print()
    header = f"{'Chỉ số Đánh giá':<32} | " + " | ".join([f"{r['name']:<24}" for r in results])
    print(header)
    print("-" * len(header))
    
    row_total = f"{'Tổng số Alert sinh ra':<32} | " + " | ".join([f"{r['total_alerts']:<24,}" for r in results])
    row_tp = f"{'True Positives':<32} | " + " | ".join([f"{r['tp']:<24,}" for r in results])
    row_fp = f"{'False Positives':<32} | " + " | ".join([f"{r['fp']:<24,}" for r in results])
    row_phases = f"{'Số giai đoạn phát hiện':<32} | " + " | ".join([f"{r['detected_phases']}/{r['total_phases']} ({r['recall']:.1f}%)".ljust(24) for r in results])
    row_prec = f"{'Precision':<32} | " + " | ".join([f"{r['precision']:.2f}%".ljust(24) for r in results])
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

    print("\nCHI TIẾT TỪNG GIAI ĐOẠN:")
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
    parser.add_argument("--attacktimes", default="alert-data-set-main/attacktimes.py", help="File attacktimes.py gốc của dataset")
    parser.add_argument("--aminer", default=None, help="File aminer json")
    parser.add_argument("--wazuh", default=None, help="File wazuh json")
    parser.add_argument("--siem-labels-dir", default="alert-data-set-main/alerts_csv/alerts_csv", help="Thư mục alert dataset đã gán nhãn TP/FP cho SIEM")
    parser.add_argument("--custom", default="detection_alerts.jsonl", help="File alerts của Custom Engine")
    parser.add_argument("--dedup-window", type=float, default=0.0, help="Cửa sổ thời gian khử trùng lặp (giây)")
    
    args = parser.parse_args()

    aminer_path = args.aminer or f"ait_ads/{args.scenario}_aminer.json"
    wazuh_path = args.wazuh or f"ait_ads/{args.scenario}_wazuh.json"
    custom_path = args.custom
    siem_labels_path = os.path.join(args.siem_labels_dir, f"{args.scenario}_alerts.txt")

    gt_template = load_ground_truth(args.labels, args.scenario, attacktimes_file=args.attacktimes)
    if not gt_template:
        return

    results = []
    
    if os.path.exists(siem_labels_path):
        results.append(eval_labeled_siem(siem_labels_path, "AMiner", gt_template, args.dedup_window))
        results.append(eval_labeled_siem(siem_labels_path, "Wazuh", gt_template, args.dedup_window))
    else:
        print(f"⚠️ Không tìm thấy SIEM label file: {siem_labels_path}; dùng đánh giá heuristic từ JSON.")
        r_aminer = eval_aminer(aminer_path, gt_template, dedup_window=args.dedup_window)
        if r_aminer: results.append(r_aminer)
        r_wazuh = eval_wazuh(wazuh_path, gt_template, dedup_window=args.dedup_window)
        if r_wazuh: results.append(r_wazuh)

    r_custom = eval_custom(custom_path, gt_template, dedup_window=args.dedup_window)
    if r_custom: results.append(r_custom)

    if results:
        print_comparison_table(results, args.scenario)

if __name__ == "__main__":
    main()
