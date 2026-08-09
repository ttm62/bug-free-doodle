# Đồ án Thạc sĩ: Phát hiện xâm nhập trái phép dựa trên phân tích đa nguồn dữ liệu

Dự án này là mã nguồn thực nghiệm cho đồ án Thạc sĩ chuyên ngành An toàn thông tin. Hệ thống tập trung vào việc thu thập, phân tích và tương quan các sự kiện bảo mật từ nhiều nguồn log khác nhau bằng công nghệ Cơ sở dữ liệu đồ thị (Graph Database - Neo4j) kết hợp với hệ thống XDR (Wazuh).

## Kiến trúc Hệ thống

Hệ thống được thiết kế theo mô hình xử lý đường ống dữ liệu (Data Pipeline) theo thời gian thực, bao gồm các thành phần:

1. **Wazuh (SIEM / XDR):** Nền tảng trung tâm dùng để cấu hình giám sát các nút (agent), thu thập các sự kiện bảo mật (FIM, rootcheck, syscheck).
2. **Vector:** Công cụ định tuyến log (Log Router) làm nhiệm vụ thu thập log thô từ máy chủ và các tệp JSON của Wazuh, sau đó đẩy liên tục về một Webhook.
3. **Go Webhook Middleware:** Mã nguồn tùy chỉnh được viết bằng ngôn ngữ Golang (`cmd/aaa/webhook.go`). Đóng vai trò là bộ phân tích cú pháp (Parser). Hệ thống hỗ trợ bóc tách:
   - `auth.log` / `syslog` (Xác thực hệ thống & Phân quyền)
   - `apache_access.log` (Truy cập Web)
   - `eve.json` (Cảnh báo mạng từ Suricata IDS)
   - `audit.log` (Kiểm toán hệ điều hành)
4. **Neo4j Graph Database:** Đóng vai trò là trung tâm Tương quan sự kiện (Event Correlation). Log phẳng được chuyển đổi thành Đồ thị tri thức (Knowledge Graph) với các Nút (IP, User, Process) và Cạnh (Hành vi).

## Bộ dữ liệu Thực nghiệm (Dataset)

Dự án sử dụng bộ dữ liệu **AIT-LDS v2.1 (Austrian Institute of Technology Log Data Set)**.
Các tệp dữ liệu được lưu trong thư mục `ait_ads/`, mô phỏng các kịch bản tấn công theo vòng đời (Kill-chain) hoàn chỉnh từ MITRE ATT&CK:
- Dò thám & Rà quét (`network_scans`, `wpscan`, `dirb`)
- Xâm nhập bước đầu (`webshell`)
- Chiếm quyền và leo thang (`cracking`, `su/sudo`)
- Tuồn dữ liệu ra ngoài (`dnsteal`)

Các tập dữ liệu tiêu biểu được sử dụng: `russellmitchell`, `santos`, `fox`.

## Hướng dẫn Khởi chạy (Quick Start)

### 1. Yêu cầu hệ thống
- Docker & Docker Compose
- Golang (phiên bản >= 1.20)
- Ít nhất 4GB RAM trống cho các container (Wazuh, Neo4j, v.v.)

### 2. Triển khai Hệ thống Cơ sở
Sử dụng Docker Compose để khởi tạo cụm Wazuh (Single-node) và các thành phần đi kèm:

```bash
cd single-node
docker-compose up -d
```

### 3. Khởi chạy Webhook Xử lý Đa Nguồn
Để khởi chạy middleware trung gian nhận log từ Vector và đẩy dữ liệu vào Neo4j:

```bash
cd cmd/aaa
go run webhook.go
```
*Lưu ý: Cần đảm bảo cơ sở dữ liệu Neo4j đang chạy và thông tin xác thực (`neo4jURL`, `neo4jUser`, `neo4jPass`) đã được cấu hình đúng.*

## Phân tích và Truy vấn Đồ thị

Thay vì viết các quy tắc (Rules) dò tìm trên log phẳng, hệ thống sử dụng ngôn ngữ truy vấn **Cypher** để tìm kiếm chuỗi tấn công thông qua mô hình đồ thị. Dưới đây là bộ truy vấn tiêu biểu phục vụ cho việc bóc tách kịch bản tấn công leo thang đặc quyền:

### 0. Khám phá Lược đồ và Cấu trúc Dữ liệu (Schema & Data Exploration)

Trước khi tiến hành phân tích các bất thường an toàn thông tin, hệ thống cần thực hiện các thao tác xác minh tính toàn vẹn của mô hình dữ liệu. Các truy vấn dưới đây phục vụ mục đích cấu trúc hóa và định lượng tập dữ liệu thực nghiệm đang được lưu trữ trên Neo4j.

**0.1. Trực quan hóa toàn bộ Lược đồ Đồ thị (Graph Schema)**
```cypher
CALL db.schema.visualization();
```
> **Đánh giá kết quả:** Trong bước khởi đầu của quá trình thực nghiệm, một yêu cầu bắt buộc là phải xác minh tính toàn vẹn của cấu trúc dữ liệu sau khi trải qua quá trình bóc tách (parsing) từ log phẳng và nạp vào cơ sở dữ liệu đồ thị Neo4j. Truy vấn này nhằm mục đích gọi các thủ tục nội bộ để truy xuất cấu trúc siêu đồ thị (Meta-graph) mặc định, từ đó xây dựng một sơ đồ biểu diễn trực quan. Kết quả trả về một mạng lưới kết nối xác nhận sự tồn tại của các loại nút (node) trọng yếu đại diện cho các thực thể trong hệ thống như `IPAddress`, `User`, `Process`, `HTTPRequest`, cùng với các cạnh liên kết định hướng (directed edges) như `REQUESTED`, `RAN_AS`, `QUERIED`. Thao tác này đóng vai trò nền tảng, giúp định hình bản đồ phân bổ dữ liệu và các luồng tương tác hợp lệ. Nhờ đó, người phân tích có cơ sở vững chắc để thiết kế các truy vấn đồ thị phức tạp ở những bước tiếp theo, đảm bảo tính chính xác tuyệt đối về mặt logic và tránh các lỗi truy vấn do không khớp cấu trúc dữ liệu (schema mismatch).

**0.2. Thống kê số lượng các thực thể và Mối quan hệ**
```cypher
MATCH (n) RETURN labels(n)[0] AS Loai_Thuc_The, count(*) AS So_Luong ORDER BY So_Luong DESC;

MATCH ()-[r]->() RETURN type(r) AS Loai_Hanh_Vi, count(*) AS So_Luong ORDER BY So_Luong DESC;
```
> **Đánh giá kết quả:** Việc phân tích định lượng các thành phần cấu thành nên đồ thị giúp phác họa bức tranh tổng thể về mức độ hoạt động của môi trường đang được giám sát. Khi thực thi các truy vấn thống kê nhằm đếm số lượng thực thể trong tập dữ liệu thực nghiệm, kết quả trả về cho thấy một sự chênh lệch và tập trung rất lớn ở các thành phần thuộc lớp mạng. Cụ thể, hệ thống ghi nhận sự tồn tại của 35.087 nút địa chỉ IP và 22.624 nút truy vấn DNS. Đi kèm với số lượng nút khổng lồ này là các mối quan hệ tương tác với tần suất dày đặc, bao gồm 43.937 kết nối truy vấn tên miền (QUERIED) và 8.356 yêu cầu truy cập giao thức web (REQUESTED). Trong khi đó, các thực thể thuộc lớp hệ điều hành như User hay Process chiếm tỷ trọng thấp hơn rất nhiều. Sự phân bổ dữ liệu bất đối xứng này phản ánh xu hướng rà quét mạng và thăm dò liên tục từ các đối tượng bên ngoài nhắm vào hệ thống. Dựa trên cơ sở phân tích định lượng này, chiến lược giám sát ban đầu được định hướng tập trung vào việc sàng lọc các hoạt động bất thường trên không gian mạng, làm tiền đề để xác định vector tấn công ban đầu (Initial Access).

### 1. Cấp độ Phát hiện Đơn nguồn (Single-Source Anomaly)

**1.1. Phát hiện Dò mật khẩu WordPress - WPCrack (Từ Apache Log)**
```cypher
MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)
WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php' OR http.uri CONTAINS 'xmlrpc.php'
WITH ip, count(req) AS scan_attempts, max(datetime(req.last_seen)) AS last_attempt
WHERE scan_attempts >= 1
RETURN ip.ip AS attacker_ip, scan_attempts, last_attempt
ORDER BY scan_attempts DESC;
```
> **Đánh giá kết quả:** Tấn công dò đoán mật khẩu (Brute-force) nhằm vào các giao diện xác thực vẫn luôn là một kỹ thuật phổ biến được các đối tượng tấn công sử dụng để giành quyền truy cập hệ thống. Dựa trên nguồn dữ liệu log của máy chủ web Apache, truy vấn Cypher được thiết kế chuyên biệt nhằm cô lập các địa chỉ IP phát sinh khối lượng lớn kết nối bất thường hướng đến các điểm cuối (endpoints) nhạy cảm như `wp-login.php` hay `xmlrpc.php`. Khi thực thi trên tập dữ liệu, kết quả phân tích đã xác định rõ ràng địa chỉ IP `172.19.131.174` là nguồn phát sinh tấn công, với tổng cộng 3.084 yêu cầu đăng nhập được ghi nhận. Đồng thời, hệ thống trích xuất được thời điểm kết thúc chuỗi truy cập này là vào lúc 04:37:25Z ngày 24/01/2022. Việc xác định chính xác địa chỉ IP của kẻ tấn công và thiết lập được mốc thời gian cụ thể cung cấp một điểm neo (pivot point) có giá trị cốt lõi. Trong thực tiễn vận hành SOC, thông tin này không chỉ dùng để thiết lập luật chặn lọc (blacklist) tại Firewall, mà còn đóng vai trò là cột mốc "thời gian 0" để hệ thống tiếp tục truy vết, phân tích xem liệu đối tượng đã vượt qua được rào cản xác thực để xâm nhập sâu hơn vào kiến trúc bên trong hay chưa.

**1.2. Phát hiện chuyển đổi tài khoản trái phép bằng lệnh `su` (Từ Auth Log)**
```cypher
MATCH (u:User {username: 'www-data'})-[r:RAN_AS {is_su: true}]->(p:Process)
RETURN u.username AS ke_thu_noi_bo, 
       r.target_user AS tai_khoan_bi_chiem, 
       p.exe AS lenh_su_dung, 
       r.last_seen AS thoi_gian;
```
> **Đánh giá kết quả:** Sau khi ghi nhận các dấu hiệu rà quét và tấn công tại lớp ứng dụng web, bước phân tích tiếp theo đòi hỏi sự chuyển dịch trọng tâm sang lớp hệ điều hành (OS) thông qua việc giám sát các bản ghi xác thực hệ thống (Auth logs). Kẻ tấn công, sau khi chiếm được quyền kiểm soát tiến trình web, thường có xu hướng tìm cách chuyển đổi định danh (substitute user - su) từ tài khoản dịch vụ cấp thấp sang tài khoản người dùng nội bộ hợp lệ nhằm thiết lập chỗ đứng vững chắc. Mục đích của truy vấn này là phát hiện các hành vi chuyển dịch định danh trái phép như vậy. Dữ liệu truy xuất từ đồ thị cho thấy tài khoản ứng dụng `www-data` đã thực hiện gọi lệnh `su` để chuyển quyền sang tài khoản người dùng `jhall` vào lúc 04:37:40Z. So sánh với các kết quả đo lường trước đó, hành vi này diễn ra chỉ cách thời điểm kết thúc đợt tấn công dò mật khẩu vỏn vẹn 15 giây. Sự tiệm cận về mặt thời gian và logic vận hành này cung cấp một cơ sở bằng chứng đanh thép, cho phép kết luận rằng máy chủ web đã chính thức bị xâm nhập (Compromised). Đối tượng tấn công đã thực hiện thành công kỹ thuật di chuyển ngang (Lateral Movement), qua đó đặt tài khoản `jhall` vào diện giám sát an ninh mức độ nghiêm trọng.

**1.3. Phát hiện lạm dụng đặc quyền Root bằng lệnh `sudo` (Từ Auth Log)**
```cypher
MATCH (u:User {username: 'jhall'})-[r:RAN_AS {is_sudo: true}]->(p:Process)
RETURN u.username AS user_thuc_thi, 
       r.command AS lenh_sudo_da_chay, 
       r.last_seen AS thoi_gian;
```
> **Đánh giá kết quả:** Việc chiếm quyền tài khoản người dùng thông thường chỉ là bước đệm trong chuỗi tấn công. Để có thể thao túng toàn diện hệ thống hoặc đánh cắp các dữ liệu nhạy cảm được bảo vệ, đối tượng tấn công bắt buộc phải thực hiện các bước leo thang đặc quyền (Privilege Escalation). Truy vấn này được thiết kế nhằm theo dõi chặt chẽ mọi nỗ lực yêu cầu cấp quyền quản trị tối cao thông qua tiện ích `sudo`. Kết quả ghi nhận thực tế cho thấy tài khoản `jhall`, ngay sau khi bị chiếm đoạt quyền điều khiển, đã tiến hành thực thi lệnh `sudo` vào lúc 04:38:06Z. Chuỗi sự kiện có tính liên tục này khẳng định quá trình leo thang đặc quyền đã hoàn tất thành công. Việc xác định được chính xác thời điểm hệ thống rơi vào tình trạng bị kiểm soát hoàn toàn mang ý nghĩa sống còn trong công tác ứng phó sự cố (Incident Response). Nó thiết lập một mốc thời gian giới hạn, theo đó, bất kỳ sự thay đổi cấu hình, tệp tin hay luồng dữ liệu nào phát sinh sau thời điểm này đều phải được xếp vào nhóm hành vi độc hại, đòi hỏi các biện pháp can thiệp và ngăn chặn khẩn cấp nhằm bảo vệ tài nguyên lõi.

**1.4. Phát hiện Rò rỉ dữ liệu qua giao thức DNS - DNSteal (Từ Suricata Log)**
```cypher
MATCH (ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)
WHERE size(dns.rrname) > 40
WITH ip, count(q) AS dns_queries, collect(DISTINCT dns.rrname)[0..3] AS sample_domains
WHERE dns_queries > 10
RETURN ip.ip AS may_chu_bi_nhiem, dns_queries AS so_luong_truy_van, sample_domains;
```
> **Đánh giá kết quả:** Ở giai đoạn cuối cùng của vòng đời tấn công (Kill-chain), mục tiêu tối thượng của kẻ gian thường là đánh cắp và tuồn dữ liệu ra ngoài (Data Exfiltration). Để qua mặt các hệ thống tường lửa thông thường, chúng thường sử dụng kỹ thuật tạo kênh truyền tải dữ liệu lén lút (Covert channel) thông qua giao thức DNS. Hệ thống sử dụng log từ thiết bị phát hiện xâm nhập Suricata kết hợp với truy vấn Cypher tập trung vào việc đo lường sự bất thường về độ dài (payload size) của các gói tin truy vấn DNS. Phân tích kết quả thực nghiệm xác định được hai máy chủ trong mạng nội bộ mang địa chỉ `192.168.230.4` và `10.143.0.103` đã thực hiện hơn 20.000 lượt truy vấn bất thường ra ngoài Internet. Đáng quan ngại hơn, phần tên miền (subdomain) của các truy vấn này đều chứa các chuỗi dữ liệu mã hóa Base64 kéo dài bất thường, đi kèm với các dấu hiệu nhận dạng của tệp tin nhạy cảm (ví dụ: định dạng `.xlsx`). Sự hiện diện của các dữ kiện này là minh chứng rõ ràng và chắc chắn nhất xác nhận rằng hành vi rò rỉ dữ liệu đang diễn ra trên quy mô lớn, đòi hỏi bộ phận an ninh mạng phải lập tức triển khai các kịch bản cô lập mạng cấp bách đối với các máy chủ bị ảnh hưởng để cầm máu dữ liệu.

**1.5. Phát hiện Dò quét Thư mục Ẩn - Dirb (Từ Apache Log)**
```cypher
MATCH (ip:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)
WHERE http.status_code = 404
WITH ip, count(req) AS not_found_count
WHERE not_found_count > 50
RETURN ip.ip AS attacker_ip, not_found_count AS so_lan_loi_404;
```
> **Đánh giá kết quả:** Việc rà quét và lập bản đồ cấu trúc thư mục của ứng dụng web là một kỹ thuật dò thám (Reconnaissance) tiêu chuẩn. Nhằm bổ sung thông tin toàn diện cho hồ sơ tấn công, hệ thống tiến hành thống kê và đo lường tần suất phát sinh mã lỗi HTTP 404 (Not Found) bắt nguồn từ cùng một địa chỉ IP. Truy vấn phát hiện địa chỉ IP nguồn `172.19.131.174` đã trực tiếp gây ra tới 7.514 mã lỗi 404. Phân tích lưu lượng này cho thấy rõ ràng đối tượng tấn công đã sử dụng các công cụ rà quét tự động (như Dirb hay Gobuster) kết hợp với các bộ từ điển lớn để tìm kiếm các tệp tin ẩn, tệp tin sao lưu (backup) hoặc các đường dẫn quản trị không được bảo vệ. Kết quả này không chỉ làm rõ phương thức hoạt động ở giai đoạn đầu của cuộc tấn công mà còn giúp hoàn thiện bức tranh về mức độ chuẩn bị và kỹ năng của đối tượng nhắm vào hệ thống.

### 2. Cấp độ Tương quan Đa nguồn (Multi-Source Temporal Correlation)

**2.1. Xâu chuỗi Xâm nhập Web (Apache) và Chiếm quyền (Auth)**
```cypher
// 1. Tìm IP tấn công WordPress (Từ Apache)
MATCH (attacker:IPAddress)-[req:REQUESTED]->(http:HTTPRequest)
WHERE http.is_scanner = true OR http.uri CONTAINS 'wp-login.php'
WITH max(datetime(req.last_seen)) AS time_wpcrack

// 2. Tương quan với lệnh chiếm quyền nội bộ (Từ Auth)
MATCH (u:User {username: 'www-data'})-[su:RAN_AS {is_su: true}]->(p:Process)
WITH time_wpcrack, u, su, p
WHERE datetime(su.last_seen) > time_wpcrack
  AND duration.inSeconds(time_wpcrack, datetime(su.last_seen)).hours <= 2
RETURN u.username AS the_luc_xam_nhap, su.target_user AS nan_nhan;
```
> **Đánh giá kết quả:** Một trong những thách thức lớn nhất của các hệ thống SIEM truyền thống là tình trạng "mệt mỏi vì cảnh báo" (Alert Fatigue) do phải xử lý hàng ngàn cảnh báo rời rạc, thiếu tính kết nối. Mô hình cơ sở dữ liệu đồ thị giải quyết bài toán này thông qua khả năng liên kết dữ liệu chéo linh hoạt giữa các tầng hệ thống khác nhau. Truy vấn tương quan đa nguồn này được xây dựng nhằm tích hợp sự kiện rà quét mạng bất thường (thu thập từ log Apache) với sự kiện thao túng đặc quyền tài khoản (thu thập từ log hệ điều hành), dựa trên điều kiện ràng buộc chặt chẽ về mặt không gian và thời gian. Kết quả thực thi cho thấy, hệ thống đã thành công trong việc ghép nối hành vi dò đoán mật khẩu (WPCrack) với sự kiện tài khoản `www-data` thực hiện lệnh `su` chiếm quyền chỉ vài chục giây sau đó. Sự liên kết tự động và chuẩn xác này giúp nâng cao đáng kể độ tin cậy của cảnh báo. Bằng cách nối nguyên nhân (dò quét) với hậu quả (chiếm quyền) thành một sự kiện thống nhất, hệ thống giúp loại trừ hoàn toàn các hoạt động rà quét bề mặt thông thường từ các bot mạng, cho phép đội ngũ phân tích tập trung nhân lực vào các mối đe dọa mang tính thực tế và có tỷ lệ chính xác (True Positive) cao.

**2.2. Xâu chuỗi Lạm dụng quyền Root (Auth) và Rò rỉ dữ liệu (Suricata)**
```cypher
// 1. Tìm khoảnh khắc gõ lệnh sudo (Auth Log)
MATCH (u:User {username: 'jhall'})-[r_sudo:RAN_AS {is_sudo: true}]->(p:Process)
WITH max(datetime(r_sudo.last_seen)) AS time_sudo

// 2. Tìm các truy vấn DNS bất thường xuất phát từ mạng nội bộ (Suricata Log)
MATCH (internal_ip:IPAddress)-[q:QUERIED]->(dns:DNSQuery)
WHERE size(dns.rrname) > 40
  AND datetime(q.last_seen) > time_sudo
  AND duration.inSeconds(time_sudo, datetime(q.last_seen)).hours <= 1
WITH internal_ip, time_sudo, count(q) AS dns_count
WHERE dns_count > 5
RETURN internal_ip.ip AS may_chu_ro_ri, time_sudo AS thoi_gian_danh_cap, dns_count;
```
> **Đánh giá kết quả:** Tính ưu việt và điểm nhấn học thuật của phương pháp tương quan đa nguồn được thể hiện rõ nét nhất qua việc kết nối hành vi lạm dụng đặc quyền trên hệ điều hành với hậu quả rò rỉ dữ liệu tại tầng mạng. Truy vấn này đối chiếu mốc thời gian khi đối tượng tấn công giành được quyền quản trị (thông qua lệnh `sudo`) với những biến động bất thường trong lưu lượng truy vấn DNS nội bộ. Kết quả phân tích đồ thị cho thấy, trong khoảng thời gian hẹp chưa đầy một giờ đồng hồ sau mốc 04:38:06Z, hệ thống đã xác định được sự tồn tại của 418 gói tin DNS mang dấu hiệu truyền tải dữ liệu trái phép ra ngoài. Việc thiết lập được một chuỗi quan hệ nhân quả liền mạch và rõ ràng từ bước leo thang đặc quyền đến kết quả thất thoát dữ liệu mang ý nghĩa cực kỳ quan trọng đối với công tác điều tra số. Cơ chế này không chỉ giúp tự động hóa quá trình xâu chuỗi sự kiện mà còn cung cấp cơ sở định lượng chính xác về mức độ tác động (Impact) của cuộc tấn công. Qua đó, nó chứng minh tính khả thi và hiệu quả vượt trội của việc áp dụng mô hình đồ thị tri thức đa nguồn so với các phương pháp tra cứu log tuyến tính và rời rạc truyền thống.

## Tác giả

Dự án được xây dựng và phát triển để phục vụ cho mục đích nghiên cứu học thuật cấp bậc Thạc sĩ.
