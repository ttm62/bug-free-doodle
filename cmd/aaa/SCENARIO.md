# russell
go run ./cmd/aaa/*.go -mode neo4j -folder russellmitchell_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7474
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file russell_alerts.jsonl -neo4j-url http://localhost:7474
python3 eval_alerts.py alerts.jsonl ait_ads/labels.csv russellmitchell
python3 plot_stats.py
python3 plot_stats_boxplot.py

# santos
go run ./cmd/aaa/*.go -mode neo4j -folder santos_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7475
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file santos_alerts.jsonl -neo4j-url http://localhost:7475
python3 eval_alerts.py alerts.jsonl ait_ads/labels.csv santos
python3 plot_stats.py
python3 plot_stats_boxplot.py

# fox
go run ./cmd/aaa/*.go -mode neo4j -folder fox_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7476
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file fox_alerts.jsonl -neo4j-url http://localhost:7476
python3 eval_alerts.py alerts.jsonl ait_ads/labels.csv fox
python3 plot_stats.py
python3 plot_stats_boxplot.py

