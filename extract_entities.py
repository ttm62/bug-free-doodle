import os
import json
import re
import argparse
from pathlib import Path

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

    print(f"🔍 Đang phân tích Ground Truth Entities cho kịch bản: {scenario_dir.name}\n")

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
                        ips, users, files, commands = extract_entities_from_line(actual_line)
                        
                        extracted_entities["Attacker_IPs"].update(ips)
                        extracted_entities["Compromised_Users"].update(users)
                        extracted_entities["Malicious_Files"].update(files)
                        extracted_entities["Malicious_Commands"].update(commands)
                except json.JSONDecodeError:
                    continue

    print("========================================")
    print("CÁC THỰC THỂ GROUND TRUTH:")
    print("========================================")
    
    print("\nIPs:")
    for ip in sorted(extracted_entities["Attacker_IPs"]):
        print(f"  - {ip}")

    print("\nUsers:")
    for user in sorted(extracted_entities["Compromised_Users"]):
        if user not in ["root"]: 
            print(f"  - {user}")
        if user == "root":
            print(f"  - root")
            
    print("\nFiles / Artifacts:")
    for f in sorted(extracted_entities["Malicious_Files"]):
        print(f"  - {f}")

    print("\nCommands:")
    for cmd in sorted(extracted_entities["Malicious_Commands"]):
        print(f"  - {cmd}")
            
    output_file = f"{scenario_dir.name}_entities.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json_data = {k: sorted(list(v)) for k, v in extracted_entities.items()}
        json.dump(json_data, f, indent=4, ensure_ascii=False)
        
    print(f"\n✅ {output_file}\n")

if __name__ == "__main__":
    main()
