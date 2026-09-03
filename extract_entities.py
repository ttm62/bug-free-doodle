import os
import json
import re
import argparse
from pathlib import Path
from datetime import datetime, timezone

def parse_log_time(log_line):
    # 1. Apache format: [24/Jan/2022:03:56:59 +0000]
    m_apache = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]', log_line)
    if m_apache:
        try:
            dt = datetime.strptime(m_apache.group(1), '%d/%b/%Y:%H:%M:%S %z')
            return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            pass

    # 2. Syslog / Auth.log format: Jan 24 04:37:40
    m_syslog = re.search(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', log_line)
    if m_syslog:
        try:
            dt = datetime.strptime('2022 ' + m_syslog.group(1), '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            pass

    # 3. Auditd format: msg=audit(1643032240.123:456)
    m_audit = re.search(r'audit\((\d+)\.', log_line)
    if m_audit:
        try:
            dt = datetime.fromtimestamp(int(m_audit.group(1)), timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            pass

    # 4. Suricata / ISO format: 2022-01-24T13:11:53.524549+0000
    m_iso = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', log_line)
    if m_iso:
        return m_iso.group(1) + 'Z'

    return ""

def extract_entities_from_line(log_line):
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
    
    if '.in-addr.arpa' in log_line:
        ips = []
    
    users = []
    
    acct_match = re.search(r'acct="([^"]+)"', log_line)
    if acct_match:
        users.append(acct_match.group(1))
        
    vpn_match = re.search(r'([a-zA-Z0-9_\-\.]+)@?\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b:[0-9]+', log_line)
    if vpn_match and not vpn_match.group(1).isdigit():
        users.append(vpn_match.group(1))
        
    su_match = re.search(r'\bsu\b.*to ([a-zA-Z0-9_\-]+)', log_line)
    if su_match and not su_match.group(1).isdigit():
        users.append(su_match.group(1))
        
    ssh_match = re.search(r'Accepted \w+ for ([a-zA-Z0-9_\-]+)', log_line)
    if ssh_match and not ssh_match.group(1).isdigit():
        users.append(ssh_match.group(1))

    files = []
    # Nếu dòng log chứa DNS query (DNSteal), lưu toàn bộ FQDN để phục vụ giải mã/tái tạo
    dns_match = re.search(r'query\[[A-Z]+\]\s+([^\s]+)', log_line)
    if dns_match:
        files.append(dns_match.group(1))
    elif '3x6-.' in log_line:
        dnsteal_match = re.search(r'(3x6-\.[^\s"]+)', log_line)
        if dnsteal_match:
            files.append(dnsteal_match.group(1))
    else:
        files = re.findall(r'[a-zA-Z0-9_\-\.]+\.(?:php|xlsx|tar\.gz|zip|sh|bash)\b', log_line)
    
    commands = []
    cmd_match = re.search(r'COMMAND=(/.+)', log_line)
    if cmd_match:
        commands.append(cmd_match.group(1))
        
    exe_match = re.search(r'exe="([^"]+)"', log_line)
    if exe_match:
        commands.append(exe_match.group(1))
        
    comm_match = re.search(r'comm="([^"]+)"', log_line)
    if comm_match:
        commands.append(comm_match.group(1))
        
    if 'systemd' in log_line and 'Started' in log_line:
        commands.append('/lib/systemd/systemd')
    
    http_match = re.search(r'(?:GET|POST) (/.*?(?:\.php|\?cmd=)) ', log_line)
    if http_match:
        files.append(http_match.group(1))

    return list(set(ips)), list(set(users)), list(set(files)), list(set(commands))

def main():
    parser = argparse.ArgumentParser(description="Trích xuất Ground Truth Entities từ AIT-LDS 2.1 Labels")
    parser.add_argument("scenario_path", help="Đường dẫn đến thư mục kịch bản (VD: fox_no-pcaps)")
    args = parser.parse_args()

    scenario_dir = Path(args.scenario_path)
    labels_dir = scenario_dir / "labels"
    gather_dir = scenario_dir / "gather"

    if not labels_dir.exists() or not gather_dir.exists():
        print(f"❌ Không tìm thấy cấu trúc labels/ và gather/ trong {scenario_dir}")
        return

    extracted_entities = {
        "Attacker_IPs": set(),
        "Compromised_Users": set(),
        "Malicious_Files": set(),
        "Malicious_Commands": set()
    }

    print(f"Đang phân tích Ground Truth Entities cho kịch bản: {scenario_dir.name}\n")

    for label_file in labels_dir.rglob("*.log"):
        if not label_file.is_file():
            continue

        rel_path = label_file.relative_to(labels_dir)
        raw_log_file = gather_dir / rel_path

        if not raw_log_file.exists():
            continue

        with open(raw_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = f.readlines()

        with open(label_file, 'r', encoding='utf-8') as f:
            for json_line in f:
                if not json_line.strip():
                    continue
                try:
                    data = json.loads(json_line)
                    line_idx = data.get("line")
                    
                    if line_idx is not None and 1 <= line_idx <= len(raw_lines):
                        actual_line = raw_lines[line_idx - 1]
                        timestamp = parse_log_time(actual_line)
                        time_prefix = f"[{timestamp}] " if timestamp else ""
                        
                        ips, users, files, commands = extract_entities_from_line(actual_line)
                        
                        for ip in ips:
                            extracted_entities["Attacker_IPs"].add(f"{time_prefix}{ip}")
                        for user in users:
                            extracted_entities["Compromised_Users"].add(f"{time_prefix}{user}")
                        for file_item in files:
                            extracted_entities["Malicious_Files"].add(f"{time_prefix}{file_item}")
                        for cmd in commands:
                            extracted_entities["Malicious_Commands"].add(f"{time_prefix}{cmd}")
                except json.JSONDecodeError:
                    continue

    # QUÉT BỔ SUNG: Vét cạn toàn bộ các gói tin DNSteal trong gather/ mà tác giả AIT-LDS bỏ sót không dán nhãn
    print("Đang quét bổ sung toàn bộ gói tin DNSteal từ gather/...")
    seen_queries = set()
    for log_path in gather_dir.rglob("*"):
        if not log_path.is_file():
            continue
        if "dnsmasq.log" in log_path.name or "eve.json" in log_path.name:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as fp:
                for line in fp:
                    if '3x6-.' in line:
                        # Chỉ lấy query để tránh trùng lặp giữa request và response
                        if 'dnsmasq' in log_path.name and 'query[' not in line:
                            continue
                        
                        timestamp = parse_log_time(line)
                        time_prefix = f"[{timestamp}] " if timestamp else ""
                        ips, users, files, commands = extract_entities_from_line(line)
                        
                        for file_item in files:
                            if file_item not in seen_queries:
                                seen_queries.add(file_item)
                                extracted_entities["Malicious_Files"].add(f"{time_prefix}{file_item}")
                        for ip in ips:
                            extracted_entities["Attacker_IPs"].add(f"{time_prefix}{ip}")

    print("========================================")
    print("CÁC THỰC THỂ GROUND TRUTH (KÈM THỜI GIAN):")
    print("========================================")
    
    print("\nIPs:")
    for ip in sorted(extracted_entities["Attacker_IPs"])[:20]:
        print(f"  - {ip}")
    if len(extracted_entities["Attacker_IPs"]) > 20:
        print(f"  ... và {len(extracted_entities['Attacker_IPs']) - 20} mục khác")

    print("\nUsers:")
    for user in sorted(extracted_entities["Compromised_Users"]):
        print(f"  - {user}")
            
    print("\nFiles / Artifacts:")
    for f in sorted(extracted_entities["Malicious_Files"])[:20]:
        print(f"  - {f}")
    if len(extracted_entities["Malicious_Files"]) > 20:
        print(f"  ... và {len(extracted_entities['Malicious_Files']) - 20} mục khác")

    print("\nCommands:")
    for cmd in sorted(extracted_entities["Malicious_Commands"])[:20]:
        print(f"  - {cmd}")
    if len(extracted_entities["Malicious_Commands"]) > 20:
        print(f"  ... và {len(extracted_entities['Malicious_Commands']) - 20} mục khác")
            
    output_file = f"{scenario_dir.name}_entities.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json_data = {k: sorted(list(v)) for k, v in extracted_entities.items()}
        json.dump(json_data, f, indent=4, ensure_ascii=False)
        
    print(f"\n✅ Đã lưu: {output_file}\n")

if __name__ == "__main__":
    main()

