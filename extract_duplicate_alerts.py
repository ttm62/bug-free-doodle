#!/usr/bin/env python3
import json
import argparse
import os
from datetime import datetime, timezone
from collections import defaultdict

def extract_wazuh_duplicates(wazuh_file, cooldown=5.0):
    if not os.path.exists(wazuh_file):
        print(f"❌ Không tìm thấy file Wazuh: {wazuh_file}")
        return [], 0, 0

    last_seen = {}
    duplicates = []
    total_alerts = 0
    kept_count = 0

    with open(wazuh_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except Exception:
                continue

            rule = alert.get("rule", {})
            if rule.get("level", 0) < 3:
                continue

            ts_str = alert.get("@timestamp") or alert.get("timestamp")
            if not ts_str:
                continue
            try:
                clean_ts = ts_str.replace("+0000", "Z").replace("Z", "+00:00")[:19]
                dt = datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)
                ts = dt.timestamp()
            except Exception:
                continue

            total_alerts += 1
            rule_id = str(rule.get("id", "unknown"))
            rule_desc = rule.get("description", "")
            
            data_obj = alert.get("data", {}) or {}
            src_ip = data_obj.get("srcip") or data_obj.get("src_ip") or "no_ip"
            
            # Lấy nội dung log cụ thể: full_log hoặc trích xuất từ data (Suricata/Apache/Syslog)
            full_log = alert.get("full_log")
            if not full_log:
                if "http" in data_obj and isinstance(data_obj["http"], dict):
                    h = data_obj["http"]
                    full_log = f"{h.get('http_method', '')} {h.get('url', '')} HTTP -> {h.get('hostname', '')} (Status: {h.get('status', '')})"
                elif "alert" in data_obj and isinstance(data_obj["alert"], dict):
                    full_log = f"Suricata Sig: {data_obj['alert'].get('signature', '')} [{data_obj.get('proto', '')} {src_ip} -> {data_obj.get('dest_ip', '')}]"
                elif data_obj:
                    full_log = json.dumps(data_obj, ensure_ascii=False)
                else:
                    full_log = rule_desc

            # Deduplication key đồng bộ chuẩn xác với compare_ids_benchmarks.py
            dedup_key = rule_id

            if dedup_key in last_seen:
                prev_ts, prev_info = last_seen[dedup_key]
                time_diff = ts - prev_ts
                if time_diff < cooldown:
                    duplicates.append({
                        "system": "Wazuh",
                        "line": line_num,
                        "timestamp": dt.isoformat(),
                        "time_diff_sec": round(time_diff, 4),
                        "key": f"Rule {rule_id}",
                        "rule_description": rule_desc,
                        "original_timestamp": prev_info["timestamp"],
                        "log_snippet": str(full_log)[:150]
                    })
                    continue

            # Kept as original/anchor
            last_seen[dedup_key] = (ts, {
                "timestamp": dt.isoformat(),
                "rule_id": rule_id,
                "src_ip": src_ip
            })
            kept_count += 1

    return duplicates, total_alerts, kept_count

def extract_aminer_duplicates(aminer_file, cooldown=5.0):
    if not os.path.exists(aminer_file):
        print(f"❌ Không tìm thấy file AMiner: {aminer_file}")
        return [], 0, 0

    last_seen = {}
    duplicates = []
    total_alerts = 0
    kept_count = 0

    with open(aminer_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except Exception:
                continue

            log_data = alert.get("LogData", {})
            timestamps = log_data.get("Timestamps", []) or log_data.get("DetectionTimestamp", [])
            if not timestamps:
                continue
            ts = float(timestamps[0])
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)

            comp = alert.get("AnalysisComponent", {})
            comp_name = comp.get("AnalysisComponentName", "")
            msg = comp.get("Message", "")
            raw = " ".join(log_data.get("RawLogData", []))

            total_alerts += 1
            dedup_key = comp_name

            if dedup_key in last_seen:
                prev_ts, prev_info = last_seen[dedup_key]
                time_diff = ts - prev_ts
                if time_diff < cooldown:
                    duplicates.append({
                        "system": "AMiner",
                        "line": line_num,
                        "timestamp": dt.isoformat(),
                        "time_diff_sec": round(time_diff, 4),
                        "key": comp_name,
                        "rule_description": msg,
                        "original_timestamp": prev_info["timestamp"],
                        "log_snippet": raw[:150]
                    })
                    continue

            # Kept
            last_seen[dedup_key] = (ts, {
                "timestamp": dt.isoformat(),
                "comp_name": comp_name
            })
            kept_count += 1

    return duplicates, total_alerts, kept_count

def print_summary(name, total, kept, dups, sample_limit=5):
    dup_count = len(dups)
    dup_percent = (dup_count / total * 100) if total > 0 else 0
    print(f"\n{'='*75}")
    print(f"🔍 BÁO CÁO TRÙNG LẶP CẢNH BÁO: {name.upper()}")
    print(f"{'='*75}")
    print(f"• Tổng số alert:            {total:,}")
    print(f"• Alert đại diện (Giữ lại): {kept:,} ({(kept/total*100):.1f}%)" if total > 0 else "")
    print(f"• Alert TRÙNG LẶP (Bỏ qua): {dup_count:,} ({dup_percent:.2f}%)")

    # Group duplicate types
    counter = defaultdict(int)
    for d in dups:
        counter[f"{d['key']} - {d['rule_description'][:40]}"] += 1

    print("\n📊 Top các loại alert bị trùng lặp nhiều nhất:")
    for k, v in sorted(counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  - [{v:,} lần] {k}")

    print(f"\n📋 Mẫu {min(sample_limit, dup_count)} cảnh báo bị loại bỏ do trùng lặp:")
    for i, d in enumerate(dups[:sample_limit], 1):
        print(f"  [{i}] Lúc {d['timestamp']} (cách alert trước {d['time_diff_sec']}s):")
        print(f"      Khóa:  {d['key']}")
        print(f"      Mô tả: {d['rule_description']}")
        print(f"      Log:   {d['log_snippet'][:90]}...\n")

def main():
    parser = argparse.ArgumentParser(description="Trích xuất các cảnh báo trùng lặp (Duplicates) của Wazuh & AMiner")
    parser.add_argument("--scenario", default="russellmitchell", help="Tên kịch bản (VD: russellmitchell, fox, santos, wardbeck, harrison, shaw, wheeler, wilson)")
    parser.add_argument("--cooldown", type=float, default=5.0, help="Cửa sổ cooldown để xác định trùng lặp (giây), mặc định 5.0")
    parser.add_argument("--system", choices=["all", "wazuh", "aminer"], default="all", help="Hệ thống cần kiểm tra (all/wazuh/aminer)")
    parser.add_argument("--output-json", default=None, help="File đường dẫn để xuất toàn bộ danh sách alert trùng lặp dưới dạng JSON")
    parser.add_argument("--samples", type=int, default=5, help="Số lượng log mẫu in ra màn hình (mặc định 5)")

    args = parser.parse_args()

    wazuh_file = f"ait_ads/{args.scenario}_wazuh.json"
    aminer_file = f"ait_ads/{args.scenario}_aminer.json"

    all_duplicates = []

    if args.system in ["all", "wazuh"]:
        dups_w, total_w, kept_w = extract_wazuh_duplicates(wazuh_file, cooldown=args.cooldown)
        if total_w > 0:
            print_summary(f"Wazuh ({args.scenario})", total_w, kept_w, dups_w, args.samples)
            all_duplicates.extend(dups_w)

    if args.system in ["all", "aminer"]:
        dups_a, total_a, kept_a = extract_aminer_duplicates(aminer_file, cooldown=args.cooldown)
        if total_a > 0:
            print_summary(f"AMiner ({args.scenario})", total_a, kept_a, dups_a, args.samples)
            all_duplicates.extend(dups_a)

    if args.output_json:
        with open(args.output_json, 'w', encoding='utf-8') as f:
            json.dump(all_duplicates, f, ensure_ascii=False, indent=2)
        print(f"💾 Đã xuất toàn bộ {len(all_duplicates):,} cảnh báo trùng lặp ra file: {args.output_json}")

if __name__ == "__main__":
    main()
