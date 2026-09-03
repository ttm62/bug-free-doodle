# santos (Port 7474)
go run ./cmd/aaa -mode neo4j -folder santos_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7474
rm -f santos_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file santos_alerts.jsonl -neo4j-url http://localhost:7474 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario santos --custom santos_alerts.jsonl
python3 eval_alerts.py santos_alerts.jsonl ait_ads/labels.csv santos
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f santos_alerts.jsonl
go run ./cmd/aaa -mode stream -folder santos_no-pcaps -neo4j-url http://localhost:7474 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file santos_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# russell (Port 7475)
go run ./cmd/aaa -mode neo4j -folder russellmitchell_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7475
rm -f russell_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file russell_alerts.jsonl -neo4j-url http://localhost:7475 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario russellmitchell --custom russellmitchell_alerts.jsonl
python3 eval_alerts.py russell_alerts.jsonl ait_ads/labels.csv russellmitchell
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f russellmitchell_alerts.jsonl
go run ./cmd/aaa -mode stream -folder russellmitchell_no-pcaps -neo4j-url http://localhost:7475 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file russellmitchell_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# fox (Port 7476)
go run ./cmd/aaa -mode neo4j -folder fox_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7476
rm -f fox_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file fox_alerts.jsonl -neo4j-url http://localhost:7476 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario fox --custom fox_alerts.jsonl
python3 eval_alerts.py fox_alerts.jsonl ait_ads/labels.csv fox
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f fox_alerts.jsonl
go run ./cmd/aaa -mode stream -folder fox_no-pcaps -neo4j-url http://localhost:7476 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file fox_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# wardbeck (Port 7477)
go run ./cmd/aaa -mode neo4j -folder wardbeck_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7477
rm -f wardbeck_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file wardbeck_alerts.jsonl -neo4j-url http://localhost:7477 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario wardbeck --custom wardbeck_alerts.jsonl
python3 eval_alerts.py wardbeck_alerts.jsonl ait_ads/labels.csv wardbeck
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f wardbeck_alerts.jsonl
go run ./cmd/aaa -mode stream -folder wardbeck_no-pcaps -neo4j-url http://localhost:7477 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file wardbeck_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# harrison (Port 7478)
go run ./cmd/aaa -mode neo4j -folder harrison_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7478
rm -f harrison_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file harrison_alerts.jsonl -neo4j-url http://localhost:7478 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario harrison --custom harrison_alerts.jsonl
python3 eval_alerts.py harrison_alerts.jsonl ait_ads/labels.csv harrison
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f harrison_alerts.jsonl
go run ./cmd/aaa -mode stream -folder harrison_no-pcaps -neo4j-url http://localhost:7478 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file harrison_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# wheeler (Port 7479)
go run ./cmd/aaa -mode neo4j -folder wheeler_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7479
rm -f wheeler_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file wheeler_alerts.jsonl -neo4j-url http://localhost:7479 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario wheeler --custom wheeler_alerts.jsonl
python3 eval_alerts.py wheeler_alerts.jsonl ait_ads/labels.csv wheeler
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f wheeler_alerts.jsonl
go run ./cmd/aaa -mode stream -folder wheeler_no-pcaps -neo4j-url http://localhost:7479 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file wheeler_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# shaw (Port 7480)
go run ./cmd/aaa -mode neo4j -folder shaw_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7480
rm -f shaw_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file shaw_alerts.jsonl -neo4j-url http://localhost:7480 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario shaw --custom shaw_alerts.jsonl
python3 eval_alerts.py shaw_alerts.jsonl ait_ads/labels.csv shaw
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f shaw_alerts.jsonl
go run ./cmd/aaa -mode stream -folder shaw_no-pcaps -neo4j-url http://localhost:7480 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file shaw_alerts.jsonl -scan-interval 1 -alert-cooldown 300

# wilson (Port 7481)
go run ./cmd/aaa -mode neo4j -folder wilson_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7481
rm -f wilson_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file wilson_alerts.jsonl -neo4j-url http://localhost:7481 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 eval_alerts.py wilson_alerts.jsonl ait_ads/labels.csv wilson
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f wilson_alerts.jsonl
go run ./cmd/aaa -mode stream -folder wilson_no-pcaps -neo4j-url http://localhost:7481 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file wilson_alerts.jsonl -scan-interval 1 -alert-cooldown 300
python3 compare_ids_benchmarks.py --scenario wilson --custom wilson_alerts.jsonl

# run webhook mode
go run ./cmd/aaa \
  -mode webhook \
  -webhook-port 5050 \
  -rules ./all_rules \
  -alerts-file webhook_alerts.jsonl \
  -scan-interval 30 \
  -neo4j-url http://localhost:7475 \
  -neo4j-user neo4j \
  -neo4j-pass admin1234

# run replay to Wazuh mode (Syslog UDP 514)
# -rate: số lượng log gửi mỗi giây , hoặc 0 để gửi nhanh nhất có thể)
go run ./cmd/aaa \
  -mode wazuh \
  -folder russellmitchell_no-pcaps \
  -wazuh-addr 127.0.0.1:514 \
  -rate 100

<!-- docker exec single-node-wazuh.manager-1 truncate -s 0 /var/ossec/logs/archives/archives.json -->
docker restart vector_shipper; docker exec single-node-wazuh.manager-1 truncate -s 0 /var/ossec/logs/archives/archives.json
