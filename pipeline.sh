source env/bin/activate

run_batch_ingest() {
  NAME=$1
  PORT=$2
  FOLDER=${3:-$1}

  echo "=== Running scenario: $NAME (Port $PORT) ==="
  go run ./cmd/aaa/*.go -mode neo4j -folder "${FOLDER}_no-pcaps" -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url "http://localhost:${PORT}"
}

run_batch_ingest_all() {
  # run_batch_ingest santos 7474
  # run_batch_ingest russellmitchell 7475
  # run_batch_ingest fox 7476
  run_batch_ingest wardbeck 7477
}

run_scenario() {
  NAME=$1
  PORT=$2
  FOLDER=${3:-$1}

  echo "=== Running scenario: $NAME (Port $PORT) ==="
  # go run ./cmd/aaa/*.go -mode neo4j -folder "${FOLDER}_no-pcaps" -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url "http://localhost:${PORT}"
  go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file "${NAME}_alerts.jsonl" -neo4j-url "http://localhost:${PORT}"

  python3 eval_alerts.py "${NAME}_alerts.jsonl" ait_ads/labels.csv "$NAME"
  python3 plot_stats.py
  python3 plot_stats_boxplot.py
}

# run_batch_ingest_all

# run_scenario santos 7474
run_scenario russellmitchell 7475
# run_scenario fox 7476
# run_scenario wardbeck 7477
