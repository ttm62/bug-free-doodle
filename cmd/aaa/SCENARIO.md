# santos (Port 7474)
go run ./cmd/aaa -mode neo4j -folder santos_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7474
rm -f santos_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file santos_alerts.jsonl -neo4j-url http://localhost:7474 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario santos --custom santos_alerts.jsonl
python3 eval_alerts.py santos_alerts.jsonl ait_ads/labels.csv santos
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f santos_alerts.jsonl
go run ./cmd/aaa -mode stream -folder santos_no-pcaps -neo4j-url http://localhost:7474 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file santos_alerts.jsonl -scan-interval 1 -alert-cooldown 300 -rate 50

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
go run ./cmd/aaa -mode stream -folder fox_no-pcaps -neo4j-url http://localhost:7476 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file fox_alerts.jsonl -scan-interval 1 -alert-cooldown 300 -rate 50

# wardbeck (Port 7477)
go run ./cmd/aaa -mode neo4j -folder wardbeck_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7477
rm -f wardbeck_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file wardbeck_alerts.jsonl -neo4j-url http://localhost:7477 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario wardbeck --custom wardbeck_alerts.jsonl
python3 eval_alerts.py wardbeck_alerts.jsonl ait_ads/labels.csv wardbeck
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f wardbeck_alerts.jsonl
go run ./cmd/aaa -mode stream -folder wardbeck_no-pcaps -neo4j-url http://localhost:7477 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file wardbeck_alerts.jsonl -scan-interval 1 -alert-cooldown 300 -rate 50

# harrison (Port 7478)
go run ./cmd/aaa -mode neo4j -folder harrison_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7478
rm -f harrison_alerts.jsonl; go run ./cmd/aaa -mode detect -rules ./all_rules -alerts-file harrison_alerts.jsonl -neo4j-url http://localhost:7478 -neo4j-user "neo4j" -neo4j-pass "admin1234"
python3 compare_ids_benchmarks.py --scenario harrison --custom harrison_alerts.jsonl
python3 eval_alerts.py harrison_alerts.jsonl ait_ads/labels.csv harrison
python3 plot_stats.py
python3 plot_stats_boxplot.py

rm -f harrison_alerts.jsonl
go run ./cmd/aaa -mode stream -folder harrison_no-pcaps -neo4j-url http://localhost:7478 -neo4j-user neo4j -neo4j-pass admin1234 -rules ./all_rules -alerts-file harrison_alerts.jsonl -scan-interval 1 -alert-cooldown 300 -rate 50

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
# -rate: số lượng log gửi mỗi giây (-rate 50, hoặc 0 để gửi nhanh nhất có thể)
go run ./cmd/aaa \
  -mode wazuh \
  -folder russellmitchell_no-pcaps \
  -wazuh-addr 127.0.0.1:514 \
  -rate 100

<!-- docker exec single-node-wazuh.manager-1 truncate -s 0 /var/ossec/logs/archives/archives.json -->
docker restart vector_shipper; docker exec single-node-wazuh.manager-1 truncate -s 0 /var/ossec/logs/archives/archives.json
