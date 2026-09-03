import json

with open('rules/rule_mega_web_killchain.json', 'r') as f:
    mega = json.load(f)

mega['tree']['query'] = "MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest) WHERE http.status_code IN [403, 404] OR http.user_agent CONTAINS 'dirb' OR http.user_agent CONTAINS 'nmap' WITH ip, count(req) AS recon_count, max(datetime(req.last_seen)) AS time_recon WHERE recon_count > 20 RETURN ip.ip AS attacker_ip, recon_count, toString(time_recon) AS time_recon ORDER BY time_recon ASC LIMIT 10"

mega['tree']['on_match']['next'][0]['query'] = "MATCH (ip:IPAddress {ip: $attacker_ip})-[req:REQUESTED]->(http:HTTPRequest) WHERE (http.uri CONTAINS '.php' OR http.is_suspicious_payload = true) AND http.status_code = 200 AND datetime(req.last_seen) >= datetime($time_recon) RETURN http.uri AS webshell_uri, toString(max(datetime(req.last_seen))) AS time_webshell ORDER BY time_webshell ASC LIMIT 10"

mega['tree']['on_match']['next'][0]['on_match']['next'][0]['query'] = "MATCH (p_web:Process)-[s:SPAWNED]->(p_shell:Process) WHERE (p_web.exe CONTAINS 'apache' OR p_web.comm CONTAINS 'apache') AND p_shell.exe IN ['/bin/bash', '/bin/sh', 'nc', 'python', 'perl'] AND datetime(s.last_seen) >= datetime($time_webshell) RETURN p_shell.exe AS shell_cmd, p_shell.pid AS shell_pid, toString(max(datetime(s.last_seen))) AS time_revshell"

with open('rules/rule_mega_web_killchain.json', 'w') as f:
    json.dump(mega, f, indent=2)

recon = {
  "rule_id": "RULE_NETWORK_RECON",
  "rule_name": "Network Scans -> Dirb",
  "enabled": True,
  "trigger_source": "syslog",
  "tree": {
    "id": "L1_TCP_SCAN",
    "name": "Quét mạng diện rộng",
    "severity": "LOW",
    "emit_alert": True,
    "query": "MATCH (ip:IPAddress)-[conn:CONNECTED|QUERIED]->(target) WITH ip, count(DISTINCT conn.dst_port) AS unique_ports, max(datetime(conn.last_seen)) AS time_netscan WHERE unique_ports > 10 RETURN ip.ip AS scanner_ip, unique_ports, toString(time_netscan) AS time_netscan ORDER BY time_netscan ASC LIMIT 5",
    "on_match": {
      "alert_message": "⚠️ [LOW] Phát hiện IP {scanner_ip} đang quét {unique_ports} cổng mạng lúc {time_netscan}",
      "next": [
        {
          "id": "L2_DIRB_SCAN",
          "name": "Dò thám thư mục (Dirb)",
          "severity": "MEDIUM",
          "emit_alert": True,
          "query": "MATCH (ip:IPAddress {ip: $scanner_ip})-[req:REQUESTED]->(http:HTTPRequest) WHERE http.status_code IN [403, 404] AND datetime(req.last_seen) >= datetime($time_netscan) WITH count(req) as dirb_count, max(datetime(req.last_seen)) AS time_dirb WHERE dirb_count > 50 RETURN dirb_count, toString(time_dirb) AS time_dirb",
          "on_match": {
            "alert_message": "🚨 [MEDIUM] IP {scanner_ip} tiếp tục dùng Dirb rà quét Web ({dirb_count} lỗi) lúc {time_dirb}!",
            "next": []
          }
        }
      ]
    }
  }
}
with open('rules/rule_network_recon.json', 'w') as f:
    json.dump(recon, f, indent=2)

cracking = {
  "rule_id": "RULE_CRACKING",
  "rule_name": "Password Cracking Phase",
  "enabled": True,
  "trigger_source": "auth_log",
  "tree": {
    "id": "L1_SSH_CRACK",
    "name": "Dò mật khẩu SSH/Hệ thống",
    "severity": "MEDIUM",
    "emit_alert": True,
    "query": "MATCH (u:User)-[fail:AUTHENTICATED_ON {status: 'failed'}]->(ip:IPAddress) WITH ip, u, count(fail) AS fails, max(datetime(fail.last_seen)) AS time_cracking WHERE fails > 5 RETURN ip.ip AS attacker_ip, u.username AS target_user, fails, toString(time_cracking) AS time_cracking LIMIT 5",
    "on_match": {
      "alert_message": "🚨 [MEDIUM] IP {attacker_ip} liên tục dò mật khẩu tài khoản {target_user} ({fails} lần) lúc {time_cracking}",
      "next": []
    }
  }
}
with open('rules/rule_cracking.json', 'w') as f:
    json.dump(cracking, f, indent=2)

service_stop = {
  "rule_id": "RULE_SERVICE_EVASION",
  "rule_name": "Defense Evasion (Service Stop)",
  "enabled": True,
  "trigger_source": "audit_log",
  "tree": {
    "id": "L1_SERVICE_STOP",
    "name": "Tắt dịch vụ bảo mật",
    "severity": "CRITICAL",
    "emit_alert": True,
    "query": "MATCH (u:User)-[exec:EXECUTED]->(p:Process) WHERE (p.command CONTAINS 'stop' OR p.command CONTAINS 'disable' OR p.command CONTAINS 'kill') AND (p.command CONTAINS 'wazuh' OR p.command CONTAINS 'suricata' OR p.command CONTAINS 'audit' OR p.command CONTAINS 'syslog' OR p.command CONTAINS 'service') RETURN u.username AS evader, p.command AS stop_cmd, toString(max(datetime(exec.last_seen))) AS time_stop LIMIT 5",
    "on_match": {
      "alert_message": "💥 [CRITICAL] CẢNH BÁO ĐỎ: Tài khoản {evader} đang cố tắt dịch vụ bằng lệnh '{stop_cmd}' lúc {time_stop}!",
      "next": []
    }
  }
}
with open('rules/rule_service_evasion.json', 'w') as f:
    json.dump(service_stop, f, indent=2)
