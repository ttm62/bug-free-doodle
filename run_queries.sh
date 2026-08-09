#!/bin/bash
function run_q() {
  echo "--- QUERY: $1 ---" >> query_results.txt
  docker exec neo4j-app cypher-shell -u neo4j -p admin1234 "$1" >> query_results.txt
  echo "" >> query_results.txt
}

run_q "MATCH (n) RETURN labels(n)[0] AS Loai_Thuc_The, count(*) AS So_Luong ORDER BY So_Luong DESC;"
run_q "MATCH ()-[r]->() RETURN type(r) AS Loai_Hanh_Vi, count(*) AS So_Luong ORDER BY So_Luong DESC;"
run_q "MATCH (p:Process) WHERE p.cmdline IS NOT NULL OR p.exe IS NOT NULL RETURN p.pid AS Process_ID, p.exe AS Executable_File, p.cmdline AS Command_Line, p.working_dir AS Working_Directory LIMIT 5;"
run_q "MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest) WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php' OR http.uri CONTAINS 'xmlrpc.php' WITH ip, count(req) AS scan_attempts, max(datetime(req.last_seen)) AS last_attempt WHERE scan_attempts >= 1 RETURN ip.ip AS attacker_ip, scan_attempts, last_attempt ORDER BY scan_attempts DESC;"
run_q "MATCH (u:User {username: 'www-data'})-[r:RAN_AS {is_su: true}]->(p:Process) RETURN u.username AS ke_thu_noi_bo, r.target_user AS tai_khoan_bi_chiem, p.exe AS lenh_su_dung, r.last_seen AS thoi_gian;"
run_q "MATCH (u:User {username: 'jhall'})-[r:RAN_AS {is_sudo: true}]->(p:Process) RETURN u.username AS user_thuc_thi, r.command AS lenh_sudo_da_chay, r.last_seen AS thoi_gian;"
run_q "MATCH (ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery) WHERE size(dns.rrname) > 40 WITH ip, count(q) AS dns_queries, collect(DISTINCT dns.rrname)[0..3] AS sample_domains WHERE dns_queries > 10 RETURN ip.ip AS may_chu_bi_nhiem, dns_queries AS so_luong_truy_van, sample_domains;"
run_q "MATCH (attacker:IPAddress)-[conn:CONNECTED_TO]->(target:Port) WITH attacker, count(DISTINCT target.number) AS ports_scanned, min(datetime(conn.last_seen)) AS start_time WHERE ports_scanned > 20 RETURN attacker.ip AS ip_quet_mang, ports_scanned AS so_cong_bi_quet, start_time;"
run_q "MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest) WHERE http.status_code = 404 WITH ip, count(req) AS not_found_count WHERE not_found_count > 50 RETURN ip.ip AS attacker_ip, not_found_count AS so_lan_loi_404;"
run_q "MATCH (ip:IPAddress)-[login:AUTHENTICATED]->(u:User) WHERE login.status = 'failed' AND login.service = 'sshd' WITH ip, u.username AS target_user, count(login) AS failed_attempts WHERE failed_attempts > 10 RETURN ip.ip AS attacker_ip, target_user, failed_attempts;"
run_q "MATCH (u:User)-[exec:EXECUTED]->(p:Process) WHERE (p.cmdline CONTAINS 'systemctl stop' OR p.cmdline CONTAINS 'service') AND (p.cmdline CONTAINS 'audit' OR p.cmdline CONTAINS 'ufw' OR p.cmdline CONTAINS 'wazuh') RETURN u.username AS user_thuc_thi, p.cmdline AS lenh_tat_dich_vu, exec.last_seen AS thoi_gian;"
run_q "MATCH (attacker:IPAddress)-[req:REQUESTED]->(http:HTTPRequest) WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php' WITH max(datetime(req.last_seen)) AS time_wpcrack MATCH (u:User {username: 'www-data'})-[su:RAN_AS {is_su: true}]->(p:Process) WITH time_wpcrack, u, su, p WHERE datetime(su.last_seen) > time_wpcrack AND duration.inSeconds(time_wpcrack, datetime(su.last_seen)).hours <= 2 RETURN u.username AS the_luc_xam_nhap, su.target_user AS nan_nhan;"
run_q "MATCH (u:User {username: 'jhall'})-[r_sudo:RAN_AS {is_sudo: true}]->(p:Process) WITH max(datetime(r_sudo.last_seen)) AS time_sudo MATCH (internal_ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery) WHERE size(dns.rrname) > 40 AND datetime(q.last_seen) > time_sudo AND duration.inSeconds(time_sudo, datetime(q.last_seen)).hours <= 1 WITH internal_ip, time_sudo, count(q) AS dns_count WHERE dns_count > 5 RETURN internal_ip.ip AS may_chu_ro_ri, time_sudo AS thoi_gian_danh_cap, dns_count;"

