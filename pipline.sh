run_scenario() {
  NAME=$1
  PORT=$2
  FOLDER=${3:-$1}

  echo "=== Running scenario: $NAME (Port $PORT) ==="
  go run ./cmd/aaa/*.go -mode neo4j -folder "${FOLDER}_no-pcaps" -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url "http://localhost:${PORT}"
  go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file "${NAME}_alerts.jsonl" -neo4j-url "http://localhost:${PORT}"

  source env/bin/activate

  python3 eval_alerts.py alerts.jsonl ait_ads/labels.csv "$NAME"
  python3 plot_stats.py
  python3 plot_stats_boxplot.py
}

run_scenario russellmitchell 7474
run_scenario santos 7475
run_scenario fox 7476

