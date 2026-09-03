#!/usr/bin/env python3
"""
recover_dnsteal_files.py
Tái tạo các tệp dữ liệu đã bị gửi qua DNS Tunneling (DNSteal)
từ file entities.json hoặc file log Suricata / dnsmasq.
"""

import os
import sys
import json
import re
import base64
import gzip
import argparse
from pathlib import Path
from collections import defaultdict

def parse_dnsteal_line(line_str):
    """
    Phân tích một dòng log hoặc entry từ entities.json để trích xuất:
    (filename, sequence, payload_chunk)
    Cấu trúc DNSteal chuỗi:
      3x6-.{seq}-.{part1}-.{part2}...-.{filename}.{domain}
    """
    if '3x6-.' not in line_str:
        return None, None, None

    # Tách theo token '-.'
    parts = line_str.split('-.')
    if len(parts) < 4:
        return None, None, None

    # Tìm index chứa '3x6'
    start_idx = -1
    for i, p in enumerate(parts):
        if p.endswith('3x6') or p == '3x6' or '3x6' in p:
            start_idx = i
            break

    if start_idx == -1 or start_idx + 2 >= len(parts):
        return None, None, None

    try:
        seq = int(parts[start_idx + 1].strip())
    except ValueError:
        return None, None, None

    # Payload là các phần ở giữa start_idx + 2 đến trước phần tử cuối cùng
    payload_parts = parts[start_idx + 2 : -1]
    payload = ''.join(payload_parts)

    # Tên file nằm ở phần tử cuối cùng
    last_part = parts[-1].strip().split()[0].rstrip('",')
    m_file = re.search(r'([a-zA-Z0-9_\-]+\.(?:docx|xlsx|pdf|txt|csv|tar|gz|zip))', last_part)
    if not m_file:
        return None, None, None

    fname = m_file.group(1)
    return fname, seq, payload

def extract_timestamp(line_str):
    """Trích xuất mốc thời gian ISO hoặc Syslog từ dòng dữ liệu"""
    m_iso = re.search(r'\[?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]?', line_str)
    if m_iso:
        return m_iso.group(1).rstrip('Z')
    m_syslog = re.search(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line_str)
    if m_syslog:
        return m_syslog.group(1)
    return ""

def recover_files(input_file, output_dir):
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)

    print(f"[*] Đang nạp dữ liệu từ: {input_file}")
    file_chunks = defaultdict(dict)
    file_timestamps = defaultdict(lambda: {"start": None, "end": None})

    # Xác định kiểu file (JSON entities hay raw log)
    is_entities_json = False
    if input_file.endswith('.json') and '_entities.json' in input_file:
        is_entities_json = True

    lines_to_process = []
    if is_entities_json:
        with open(input_file, 'r', encoding='utf-8') as fp:
            data = json.load(fp)
            lines_to_process = data.get("Malicious_Files", [])
            print(f"[*] Đã nạp {len(lines_to_process)} mục từ Malicious_Files.")
    else:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as fp:
            for l in fp:
                if '3x6-.' in l:
                    lines_to_process.append(l)
            print(f"[*] Đã tìm thấy {len(lines_to_process)} gói tin DNSteal trong tệp log.")

    for line in lines_to_process:
        fname, seq, payload = parse_dnsteal_line(line)
        if fname and seq is not None and payload:
            file_chunks[fname][seq] = payload
            ts = extract_timestamp(line)
            if ts:
                if file_timestamps[fname]["start"] is None or ts < file_timestamps[fname]["start"]:
                    file_timestamps[fname]["start"] = ts
                if file_timestamps[fname]["end"] is None or ts > file_timestamps[fname]["end"]:
                    file_timestamps[fname]["end"] = ts

    print(f"[+] Tìm thấy tổng cộng {len(file_chunks)} tệp tin độc hại.")
    print("-" * 92)
    print(f"{'TÊN TỆP TIN':<26} | {'CHUNKS':<8} | {'THỜI GIAN TUỒN DỮ LIỆU':<35} | KẾT QUẢ")
    print("-" * 92)

    success_count = 0
    for fname in sorted(file_chunks.keys()):
        chunks = file_chunks[fname]
        total_seq = len(chunks)
        min_seq = min(chunks.keys())
        max_seq = max(chunks.keys())

        missing = [i for i in range(min_seq, max_seq + 1) if i not in chunks]

        t_start = file_timestamps[fname]["start"] or ""
        t_end = file_timestamps[fname]["end"] or ""
        time_range = f"{t_start} -> {t_end}" if t_start and t_end else "Không xác định"

        if min_seq != 0 or missing:
            print(f"{fname:<26} | {total_seq:>3} seq | {time_range:<35} | ⚠️ Thiếu chunk (min={min_seq}, miss={len(missing)})")
            continue

        full_b64 = ''.join(chunks[i] for i in range(max_seq + 1)).replace('*', '+')
        pad = len(full_b64) % 4
        if pad:
            full_b64 += '=' * (4 - pad)

        try:
            raw_data = base64.b64decode(full_b64)
            # Thử giải nén gzip trước, nếu không phải gzip (ví dụ docx/xlsx được gửi raw) thì lấy dữ liệu thô
            try:
                decompressed = gzip.decompress(raw_data)
            except Exception:
                decompressed = raw_data

            file_out_path = out_path / fname
            with open(file_out_path, 'wb') as f_out:
                f_out.write(decompressed)

            success_count += 1
            size_kb = len(decompressed) / 1024
            print(f"{fname:<26} | {total_seq:>3} seq | {time_range:<35} | ✅ Phục hồi ({size_kb:.1f} KB)")
        except Exception as e:
            print(f"{fname:<26} | {total_seq:>3} seq | {time_range:<35} | ❌ Lỗi giải mã: {e}")

    print("-" * 92)
    print(f"\n🎉 HOÀN TẤT: Đã tái tạo thành công {success_count}/{len(file_chunks)} tệp tin ra thư mục '{output_dir}/'!")

def main():
    parser = argparse.ArgumentParser(description="Tái tạo nguyên vẹn tệp dữ liệu bị đánh cắp qua DNSteal")
    parser.add_argument("input_file", help="Đường dẫn đến file entities.json hoặc tệp log (eve.json, dnsmasq.log)")
    parser.add_argument("--output", "-o", default="recovered_exfiltrated_files", help="Thư mục xuất file phục hồi")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"❌ Không tìm thấy tệp: {args.input_file}")
        sys.exit(1)

    recover_files(args.input_file, args.output)

if __name__ == "__main__":
    main()
