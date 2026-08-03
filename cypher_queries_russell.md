# Bộ Truy Vấn Cypher: Kịch Bản Kẻ Thù Nội Bộ (Russell Mitchell)

Đây là các câu lệnh Cypher được viết "đo ni đóng giày" cho bộ dữ liệu `russellmitchell` của bạn, bám sát theo chuỗi MITRE ATT&CK: **Initial Access (Apache) -> Privilege Escalation (Auth) -> Exfiltration (Suricata)**.

---

## 1. PHÁT HIỆN ĐƠN NGUỒN (Single-Source Detection)

### 1.1. Dò mật khẩu WordPress - WPCrack (Chỉ dùng Apache Log)
Phát hiện một địa chỉ IP (Attacker) liên tục spam các request vào trang đăng nhập của WordPress (`wp-login.php`) với số lượng lớn.
```cypher
MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)
WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php' OR http.uri CONTAINS 'xmlrpc.php'
WITH ip, count(req) AS scan_attempts, max(datetime(req.last_seen)) AS last_attempt
WHERE scan_attempts >= 1
RETURN ip.ip AS attacker_ip, scan_attempts, last_attempt
ORDER BY scan_attempts DESC;
```

### 1.2. Chuyển đổi tài khoản trái phép bằng `su` (Chỉ dùng Auth Log)
Bắt khoảnh khắc tài khoản cấp thấp (`www-data`) leo quyền sang tài khoản nhân viên (`jhall`).
```cypher
MATCH (u:User {username: 'www-data'})-[r:RAN_AS {is_su: true}]->(p:Process)
RETURN u.username AS ke_thu_noi_bo, 
       r.target_user AS tai_khoan_bi_chiem, 
       p.exe AS lenh_su_dung, 
       r.last_seen AS thoi_gian;
```

### 1.3. Lạm dụng đặc quyền Root bằng `sudo` (Chỉ dùng Auth Log)
Tài khoản bị chiếm (`jhall`) lén lút thực thi quyền Root để đọc trộm cấu hình hệ thống (hoặc file shadow).
```cypher
MATCH (u:User {username: 'jhall'})-[r:RAN_AS {is_sudo: true}]->(p:Process)
RETURN u.username AS user_thuc_thi, 
       r.command AS lenh_sudo_da_chay, 
       r.last_seen AS thoi_gian;
```

### 1.4. Rò rỉ dữ liệu qua DNS - DNSteal (Chỉ dùng Suricata Log)
Phát hiện kỹ thuật giấu dữ liệu vào các tên miền ảo (Base64) để tuồn ra ngoài mạng. Các truy vấn DNS này thường có độ dài bất thường (trên 40 ký tự) và bị Suricata gán nhãn cảnh báo.
```cypher
MATCH (ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)
WHERE size(dns.rrname) > 40
WITH ip, count(q) AS dns_queries, collect(DISTINCT dns.rrname)[0..3] AS sample_domains
WHERE dns_queries > 10
RETURN ip.ip AS may_chu_bi_nhiem, dns_queries AS so_luong_truy_van, sample_domains;
```

---

## 2. PHÁT HIỆN ĐA NGUỒN (Multi-Source Fusion Detection)

Mục đích của việc nối đa nguồn là vẽ ra toàn bộ chuỗi tấn công (Kill-chain) trong một khung thời gian cụ thể, giúp giảm thiểu cảnh báo giả.

### 2.1. Nối WPCrack (Apache) và Chiếm quyền (Auth)
Tìm kiếm chuỗi sự kiện: Một IP càn quét trang đăng nhập WordPress, và chỉ trong vòng vài giờ sau đó, một lệnh `su` được thực thi bởi user `www-data` trên cùng máy chủ đó.
```cypher
// 1. Tìm IP tấn công WordPress (Từ Apache)
MATCH (attacker:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)
WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php'
WITH max(datetime(req.last_seen)) AS time_wpcrack

// 2. Tìm lệnh chiếm quyền nội bộ (Từ Auth)
MATCH (u:User {username: 'www-data'})-[su:RAN_AS {is_su: true}]->(p:Process)
WITH time_wpcrack, u, su, p
WHERE datetime(su.last_seen) > time_wpcrack
  // Khoảng cách giữa 2 sự kiện là dưới 2 giờ
  AND duration.inSeconds(time_wpcrack, datetime(su.last_seen)).hours <= 2

RETURN u.username AS the_luc_xam_nhap, 
       su.target_user AS nan_nhan, 
       time_wpcrack AS thoi_gian_pha_pass_web, 
       su.last_seen AS thoi_gian_chiem_quyen;
```

### 2.2. Nối Chiếm quyền (Auth) và Rò rỉ dữ liệu (Suricata)
Tìm kiếm chuỗi sự kiện: Tài khoản bị chiếm quyền vừa gõ lệnh `sudo` đọc trộm dữ liệu, ngay sau đó máy chủ phát sinh hàng loạt luồng DNS bất thường tuồn dữ liệu ra ngoài.
```cypher
// 1. Tìm khoảnh khắc gõ lệnh sudo (Auth Log)
MATCH (u:User {username: 'jhall'})-[r_sudo:RAN_AS {is_sudo: true}]->(p:Process)
WITH max(datetime(r_sudo.last_seen)) AS time_sudo

// 2. Tìm các truy vấn DNS bất thường xuất phát từ mạng nội bộ (Suricata Log)
MATCH (internal_ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)
WHERE size(dns.rrname) > 40
  AND datetime(q.last_seen) > time_sudo
  // Rò rỉ diễn ra trong vòng 1 giờ sau khi đọc trộm
  AND duration.inSeconds(time_sudo, datetime(q.last_seen)).hours <= 1

WITH internal_ip, time_sudo, count(q) AS dns_count
WHERE dns_count > 5
RETURN internal_ip.ip AS may_chu_ro_ri, 
       time_sudo AS thoi_gian_danh_cap_du_lieu, 
       dns_count AS so_goi_tin_bi_tuon_ra;
```

### 2.3. BỨC TRANH TOÀN CẢNH KỊCH BẢN (Full Kill-chain Graph)
Vẽ lại toàn bộ sơ đồ đồ thị từ bước WPCrack đến SU, SUDO, và DNS Exfiltration. (Sử dụng lệnh này để chụp ảnh màn hình đưa vào báo cáo luận văn).
```cypher
MATCH path1 = (attacker:IPAddress)-[req:REQUESTED]->(http:HTTPRequest {uri: '/wp-login.php'})
MATCH path2 = (u:User {username: 'www-data'})-[su:RAN_AS {is_su: true}]->(p1:Process)
MATCH path3 = (u2:User {username: 'jhall'})-[sudo:RAN_AS {is_sudo: true}]->(p2:Process)
MATCH path4 = (internal:IPAddress)-[q:QUERIED]->(dns:DNSQuery)
WHERE size(dns.rrname) > 40
RETURN path1, path2, path3, path4
LIMIT 50;
```
