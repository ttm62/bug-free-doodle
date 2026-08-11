# Hệ Thống Tập Luật Đa Nguồn (all_rules)

Dưới đây là lưu đồ tự động tạo cho các tập luật trong thư mục này.

## RULE_CRACKING: Password Cracking Phase
**File:** `rule_cracking.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_SSH_CRACK ["Lớp 1"]
        L1_SSH_CRACK["<b>Dò mật khẩu SSH/Hệ thống</b><br/><hr/><i>🔍 MẪU: (u:User)-[fail:AUTHENTICATED_ON {status: 'failed'}]->(ip:IPAddress)<br/>⚙️ LỌC: size(fail_times) >= 5 AND duration.between(fail_times[0], fa<br/>&nbsp;&nbsp;&nbsp;&nbsp;il_times[4]).minutes <= 5</i>"]:::medium
    end
```

## RULE_CREDENTIAL_THEFT_SHADOW: Web/SSH Intrusion -> Process Accesses /etc/shadow or Sensitive Files
**File:** `rule_credential_theft.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_SENSITIVE_ACCESS ["Lớp 1"]
        L1_SENSITIVE_ACCESS["<b>Kiểm tra Tiến Trình Đọc File Mật Khẩu Băm</b><br/><hr/><i>🔍 MẪU: (p:Process)-[:READ]->(f:File {is_sensitive: true})</i>"]:::high
    end
    subgraph Layer_L2_SHADOW_EXFILTRATION ["Lớp 2"]
        L2_SHADOW_EXFILTRATION["<b>Kiểm tra Đọc File /etc/shadow Bởi Tiến Trình Không Phải Sysdaemon</b><br/><hr/><i>🔍 MẪU: (u:User)-[:EXECUTED]->(parent:Process)-[:SPAWNS]->(p:Process {exe: $proc_exe})-[:READ]->(f:File {path: '/etc/shadow'})<br/>⚙️ LỌC: parent.exe CONTAINS 'apache2' OR parent.exe CONTAINS 'bash' <br/>&nbsp;&nbsp;&nbsp;&nbsp;OR parent.exe CONTAINS 'python' OR u.username <> 'root'</i>"]:::critical
    end
    L1_SENSITIVE_ACCESS ==> L2_SHADOW_EXFILTRATION
```

## GENERIC_ROOTKIT_MODULE: Phát hiện chung: Tải Module Nhân hệ điều hành (Rootkit/Kernel Module)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_KERNEL_MODULE_LOAD ["Lớp 1"]
        L1_KERNEL_MODULE_LOAD["<b>Nhận diện lệnh insmod/modprobe</b><br/><hr/><i>🔍 MẪU: (u:User)-[exec:EXECUTED]->(p:Process)<br/>⚙️ LỌC: p.exe IN ['insmod', 'modprobe', '/sbin/insmod', '/sbin/modpr<br/>&nbsp;&nbsp;&nbsp;&nbsp;obe']</i>"]:::high
    end
```

## GENERIC_SSH_PERSISTENCE: Phát hiện chung: Cấy khóa SSH trái phép (SSH Persistence)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_AUTH_KEYS_MOD ["Lớp 1"]
        L1_AUTH_KEYS_MOD["<b>Thay đổi Authorized Keys</b><br/><hr/><i>🔍 MẪU: (p:Process)-[w:WRITE]->(f:File)<br/>⚙️ LỌC: f.path CONTAINS '.ssh/authorized_keys'</i>"]:::high
    end
```

## GENERIC_FIM_PERSISTENCE: Phát hiện chung: Mã độc chạy ngầm -> Sửa đổi file hệ thống -> Gọi về máy chủ C2
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_SUSPICIOUS_DROPPER ["Lớp 1"]
        L1_SUSPICIOUS_DROPPER["<b>Thực thi File lạ từ thư mục Tạm (/tmp)</b><br/><hr/><i>🔍 MẪU: (u:User)-[exec:EXECUTED]->(p:Process)<br/>⚙️ LỌC: p.exe CONTAINS '/tmp/' OR p.exe CONTAINS '/var/tmp/' OR p.ex<br/>&nbsp;&nbsp;&nbsp;&nbsp;e CONTAINS '/dev/shm/'</i>"]:::medium
    end
    subgraph Layer_L2_PERSISTENCE_FIM ["Lớp 2"]
        L2_PERSISTENCE_FIM["<b>Ghi đè file hệ thống (Persistence)</b><br/><hr/><i>🔍 MẪU: (p2:Process {exe: $payload_path})-[w:WRITE]->(f:File)<br/>⚙️ LỌC: f.path CONTAINS 'cron' OR f.path CONTAINS 'rc.local' OR f.pa<br/>&nbsp;&nbsp;&nbsp;&nbsp;th CONTAINS 'init.d' OR f.path CONTAINS 'systemd' OR f.path <br/>&nbsp;&nbsp;&nbsp;&nbsp;CONTAINS '.bashrc'</i>"]:::high
    end
    L1_SUSPICIOUS_DROPPER ==> L2_PERSISTENCE_FIM
    subgraph Layer_L3_C2_CONNECTION ["Lớp 3"]
        L3_C2_CONNECTION["<b>Kết nối C2 (Command & Control)</b><br/><hr/><i>🔍 MẪU: (p3:Process {exe: $payload_path})-[net:REQUESTED|QUERIED]->(ip:IPAddress)</i>"]:::critical
    end
    L2_PERSISTENCE_FIM ==> L3_C2_CONNECTION
```

## GENERIC_DATA_STAGING: Phát hiện chung: Đóng gói dữ liệu chuẩn bị tuồn ra ngoài (Data Staging)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_ARCHIVE_DATA ["Lớp 1"]
        L1_ARCHIVE_DATA["<b>Nén dữ liệu dung lượng lớn</b><br/><hr/><i>🔍 MẪU: (u:User)-[exec:EXECUTED]->(p:Process)-[w:WRITE]->(f:File)<br/>⚙️ LỌC: p.exe IN ['tar', 'zip', 'rar', '7z', 'gzip'] AND (f.path CON<br/>&nbsp;&nbsp;&nbsp;&nbsp;TAINS '/tmp/' OR f.path CONTAINS '/dev/shm/' OR f.path CONTA<br/>&nbsp;&nbsp;&nbsp;&nbsp;INS '/var/tmp/')</i>"]:::medium
    end
```

## GENERIC_DDOS_HTTP: Phát hiện chung: Tấn công từ chối dịch vụ (DoS/DDoS) qua HTTP
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_HTTP_FLOOD ["Lớp 1"]
        L1_HTTP_FLOOD["<b>Nhận diện Flood Requests</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)<br/>⚙️ LỌC: req_count > 5000</i>"]:::high
    end
```

## RULE_SANTOS_DNSTEAL: Standalone DNSteal (Santos)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_DNSTEAL ["Lớp 1"]
        L1_DNSTEAL["<b>Rò rỉ dữ liệu qua DNS độc lập</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)<br/>⚙️ LỌC: size(dns.rrname) > 30</i>"]:::critical
    end
```

## RULE_SANTOS_PRIVESC: Standalone Privilege Escalation (Santos)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_PRIVESC ["Lớp 1"]
        L1_PRIVESC["<b>Leo quyền độc lập</b><br/><hr/><i>🔍 MẪU: (u:User)-[r:RAN_AS]->(p:Process)<br/>⚙️ LỌC: r.is_su = true OR r.is_sudo = true OR r.target_user = 'root'</i>"]:::high
    end
```

## RULE_SANTOS_CRACKING: Web/FTP Cracking Phase (Santos)
**File:** `rule_generics_combined.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_GENERIC_CRACK ["Lớp 1"]
        L1_GENERIC_CRACK["<b>Dò mật khẩu mở rộng</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)<br/>⚙️ LỌC: http.status_code = 401 OR http.status_code = 403 OR http.sta<br/>&nbsp;&nbsp;&nbsp;&nbsp;tus_code = 404</i>"]:::medium
    end
```

## RULE_MEGA_WEB_KILLCHAIN: Recon (Dirb) -> Webshell Upload -> RCE / Reverse Shell
**File:** `rule_mega_web_killchain.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_WEB_RECON ["Lớp 1"]
        L1_WEB_RECON["<b>Nhận diện rà quét Web (Dirb/Nmap)</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)<br/>⚙️ LỌC: http.status_code IN [403, 404] OR http.user_agent CONTAINS '<br/>&nbsp;&nbsp;&nbsp;&nbsp;dirb' OR http.user_agent CONTAINS 'nmap'</i>"]:::low
    end
    subgraph Layer_L2_WEBSHELL_UPLOAD ["Lớp 2"]
        L2_WEBSHELL_UPLOAD["<b>Chèn Webshell thành công</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress {ip: $attacker_ip})-[req:REQUESTED]->(http:HTTPRequest)<br/>⚙️ LỌC: (http.uri CONTAINS '.php' OR http.is_suspicious_payload = tr<br/>&nbsp;&nbsp;&nbsp;&nbsp;ue) AND http.status_code = 200 AND datetime(req.last_seen) ><br/>&nbsp;&nbsp;&nbsp;&nbsp;= datetime($time_recon)</i>"]:::medium
    end
    L1_WEB_RECON ==> L2_WEBSHELL_UPLOAD
    subgraph Layer_L3_REVERSE_SHELL ["Lớp 3"]
        L3_REVERSE_SHELL["<b>Kích hoạt Reverse Shell</b><br/><hr/><i>🔍 MẪU: (p_web:Process)-[s:SPAWNED]->(p_shell:Process)<br/>⚙️ LỌC: (p_web.exe CONTAINS 'apache' OR p_web.comm CONTAINS 'apache'<br/>&nbsp;&nbsp;&nbsp;&nbsp;) AND p_shell.exe IN ['/bin/bash', '/bin/sh', 'nc', 'python'<br/>&nbsp;&nbsp;&nbsp;&nbsp;, 'perl'] AND datetime(s.last_seen) >= datetime($time_webshe<br/>&nbsp;&nbsp;&nbsp;&nbsp;ll)</i>"]:::critical
    end
    L2_WEBSHELL_UPLOAD ==> L3_REVERSE_SHELL
```

## RULE_RCE_CMD_EXECUTION_FILE_WRITE: Web Exploit -> Remote Command Execution -> File Dropped in /tmp
**File:** `rule_rce_cmd_execution.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_WEB_POST ["Lớp 1"]
        L1_WEB_POST["<b>Kiểm tra HTTP POST Request Mạng</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[req_rel:REQUESTED]->(req:HTTPRequest)<br/>⚙️ LỌC: req.method = 'POST'</i>"]:::low
    end
    subgraph Layer_L2_CMD_EXECUTION ["Lớp 2"]
        L2_CMD_EXECUTION["<b>Kiểm tra Tiến Trình Thực Thi Lệnh Shell</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress {ip: $attacker_ip})-[req_rel:REQUESTED]->(req:HTTPRequest)<br/>⚙️ LỌC: (p_web.exe CONTAINS 'apache' OR p_web.comm CONTAINS 'apache'<br/>&nbsp;&nbsp;&nbsp;&nbsp;) AND (p_sh.exe IN ['/bin/sh', '/bin/bash', 'python', 'perl'<br/>&nbsp;&nbsp;&nbsp;&nbsp;, 'nc'] OR p_sh.comm IN ['sh', 'bash', 'python', 'perl', 'nc<br/>&nbsp;&nbsp;&nbsp;&nbsp;']) AND datetime(spawn_rel.timestamp) >= datetime(req_rel.ti<br/>&nbsp;&nbsp;&nbsp;&nbsp;mestamp) AND duration.inSeconds(datetime(req_rel.timestamp),<br/>&nbsp;&nbsp;&nbsp;&nbsp; datetime(spawn_rel.timestamp)).seconds < 60</i>"]:::high
    end
    L1_WEB_POST ==> L2_CMD_EXECUTION
    subgraph Layer_L3_TMP_FILE_DROP ["Lớp 3"]
        L3_TMP_FILE_DROP["<b>Kiểm tra Ghi File Độc Hại Vào Thư Mục Tạm /tmp</b><br/><hr/><i>🔍 MẪU: (p:Process {pid: $sh_pid})-[:SPAWNED|EXECUTED*0..3]->(p2:Process)-[w:WRITE]->(f:File)<br/>⚙️ LỌC: f.path STARTS</i>"]:::critical
    end
    L2_CMD_EXECUTION ==> L3_TMP_FILE_DROP
```

## RULE_INSIDER_THREAT_MULTI_BRANCH: WPCrack -> Privilege Escalation -> (Root Access / DNS Exfiltration)
**File:** `rule_russell_insider.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_WPCRACK ["Lớp 1"]
        L1_WPCRACK["<b>Phát hiện WPCrack</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)<br/>⚙️ LỌC: http.is_scanner = true OR http.uri CONTAINS 'wp-login.php' O<br/>&nbsp;&nbsp;&nbsp;&nbsp;R http.is_suspicious_payload = true</i>"]:::low
    end
    subgraph Layer_L2_SU_ESCALATION ["Lớp 2"]
        L2_SU_ESCALATION["<b>Chuyển tài khoản trái phép bằng su</b><br/><hr/><i>🔍 MẪU: (u:User)-[su:RAN_AS {is_su: true}]->(p:Process)<br/>⚙️ LỌC: u.username IN ['www-data', 'apache', 'nginx', 'tomcat', 'nob<br/>&nbsp;&nbsp;&nbsp;&nbsp;ody', 'daemon'] AND datetime(su.last_seen) >= datetime($time<br/>&nbsp;&nbsp;&nbsp;&nbsp;_wpcrack) AND duration.inSeconds(datetime($time_wpcrack), da<br/>&nbsp;&nbsp;&nbsp;&nbsp;tetime(su.last_seen)).hours <= 4</i>"]:::medium
    end
    L1_WPCRACK ==> L2_SU_ESCALATION
    subgraph Layer_L3A_ROOT_SUDO ["Lớp 3"]
        L3A_ROOT_SUDO["<b>Lạm dụng Sudo</b><br/><hr/><i>🔍 MẪU: (u:User {username: $compromised_user})-[sudo:RAN_AS {is_sudo: true}]->(p:Process)<br/>⚙️ LỌC: datetime(sudo.last_seen) >= datetime($time_su)</i>"]:::critical
    end
    L2_SU_ESCALATION ==> L3A_ROOT_SUDO
    subgraph Layer_L3B_DNS_EXFIL ["Lớp 3"]
        L3B_DNS_EXFIL["<b>Tuồn dữ liệu qua DNS</b><br/><hr/><i>🔍 MẪU: (ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)<br/>⚙️ LỌC: size(dns.rrname) > 40 AND datetime(q.last_seen) >= datetime(<br/>&nbsp;&nbsp;&nbsp;&nbsp;$time_su)</i>"]:::high
    end
    L2_SU_ESCALATION ==> L3B_DNS_EXFIL
```

## RULE_SERVICE_EVASION: Defense Evasion (Service Stop)
**File:** `rule_service_evasion.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_SERVICE_STOP ["Lớp 1"]
        L1_SERVICE_STOP["<b>Tắt dịch vụ bảo mật</b><br/><hr/><i>🔍 MẪU: (u:User)-[exec:EXECUTED]->(p:Process)<br/>⚙️ LỌC: (p.command CONTAINS 'stop' OR p.command CONTAINS 'disable' O<br/>&nbsp;&nbsp;&nbsp;&nbsp;R p.command CONTAINS 'kill') AND (p.command CONTAINS 'wazuh'<br/>&nbsp;&nbsp;&nbsp;&nbsp; OR p.command CONTAINS 'suricata' OR p.command CONTAINS 'aud<br/>&nbsp;&nbsp;&nbsp;&nbsp;it' OR p.command CONTAINS 'syslog' OR p.command CONTAINS 'se<br/>&nbsp;&nbsp;&nbsp;&nbsp;rvice')</i>"]:::critical
    end
```

## RULE_SSH_BRUTEFORCE_TO_PIVOT: SSH Brute-force -> Successful Login -> Lateral Movement Pivot
**File:** `rule_ssh_bruteforce_pivot.json`

```mermaid
graph TD
    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;
    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;

    subgraph Layer_L1_SSH_FAILED ["Lớp 1"]
        L1_SSH_FAILED["<b>Kiểm tra Dò Mật Khẩu SSH Thất Bại</b><br/><hr/><i>🔍 MẪU: (u:User)-[r:AUTHENTICATED_ON {status: 'failed'}]->(ip:IPAddress)<br/>⚙️ LỌC: failed_count >= 5</i>"]:::low
    end
    subgraph Layer_L2_SSH_SUCCESS ["Lớp 2"]
        L2_SSH_SUCCESS["<b>Kiểm tra Đăng Nhập SSH Thành Công Ngay Sau Đó</b><br/><hr/><i>🔍 MẪU: (u:User {username: $target_user})-[r:AUTHENTICATED_ON {status: 'success'}]->(h:Host)<br/>⚙️ LỌC: datetime(r.timestamp) > $last_fail_time AND duration.inSecon<br/>&nbsp;&nbsp;&nbsp;&nbsp;ds($last_fail_time, datetime(r.timestamp)).seconds < 3600</i>"]:::medium
    end
    L1_SSH_FAILED ==> L2_SSH_SUCCESS
    subgraph Layer_L3_LATERAL_PIVOT ["Lớp 3"]
        L3_LATERAL_PIVOT["<b>Kiểm tra Di Chuyển Ngang Sang Máy Chủ Nội Bộ Khác</b><br/><hr/><i>🔍 MẪU: (u:User {username: $target_user})-[a1:AUTHENTICATED_ON]->(h1:Host {hostname: $compromised_host})<br/>⚙️ LỌC: h1.hostname <> h2.hostname AND datetime(a2.timestamp) > $suc<br/>&nbsp;&nbsp;&nbsp;&nbsp;cess_time AND duration.inSeconds($success_time, datetime(a2.<br/>&nbsp;&nbsp;&nbsp;&nbsp;timestamp)).seconds < 86400</i>"]:::critical
    end
    L2_SSH_SUCCESS ==> L3_LATERAL_PIVOT
```

