source env/bin/activate

wait_neo4j() {
  local PORT=$1
  echo -n "[*] Waiting for Neo4j on port $PORT to be ready..."
  for i in {1..30}; do
    if curl -s "http://localhost:${PORT}" > /dev/null 2>&1; then
      echo " Ready!"
      return 0
    fi
    echo "."
    sleep 1
  done
  echo " Timeout waiting for Neo4j on port $PORT!"
  return 1
}

run_stream_benchmark() {
  NAME=$1
  PORT=$2
  SERVICE=${3:-"neo4j_${NAME}"}
  FOLDER=${4:-"${NAME}_no-pcaps"}

  echo "=== Scenario: $NAME (Port: $PORT, Service: $SERVICE) ==="

  # Dừng container và xóa database cũ nếu có
  echo "[*] Cleaning up existing container & data for $NAME..."
  CONTAINER_NAME="neo4j-app-${NAME}"
  DATA_DIR="neo4j_${NAME}"
  if [ "$NAME" = "russellmitchell" ]; then
    CONTAINER_NAME="neo4j-app-russell"
    DATA_DIR="neo4j_russell"
  fi

  docker rm -f "$CONTAINER_NAME" > /dev/null 2>&1 || true

  if [ -d "neo4j/${DATA_DIR}" ]; then
    chmod -R u+w "neo4j/${DATA_DIR}" > /dev/null 2>&1 || true
    rm -rf "neo4j/${DATA_DIR}"
  fi
  (cd neo4j && docker-compose up -d "$SERVICE")
  wait_neo4j "$PORT"

  rm -f "${NAME}_alerts.jsonl"
  go run ./cmd/aaa/*.go -mode stream \
    -folder "$FOLDER" \
    -neo4j-url "http://localhost:${PORT}" \
    -neo4j-user "neo4j" \
    -neo4j-pass "admin1234" \
    -rules ./all_rules \
    -alerts-file "${NAME}_alerts.jsonl" \
    -scan-interval 1 \
    -alert-cooldown 300

  # python3 compare_ids_benchmarks.py --scenario "$NAME" --custom "${NAME}_alerts.jsonl"
  python3 compare_ids_benchmarks.py --scenario "$NAME" --custom "${NAME}_alerts.jsonl" --labels ait_ads/labels2.csv

  # source env/bin/activate
  # python3 eval_alerts.py "${NAME}_alerts.jsonl" ait_ads/labels.csv "$NAME"
  # python3 plot_stats.py
  # python3 plot_stats_boxplot.py
}

extract_and_recover_dnsteal() {
  local NAME=$1
  local FOLDER=${2:-"${NAME}_no-pcaps"}
  local ENTITIES_FILE="${FOLDER}_entities.json"
  local OUT_DIR=${3:-"recovered_${NAME}"}

  echo "=== Extracting entities & recovering DNSteal files for: $NAME ==="
  python3 extract_entities.py "$FOLDER"
  python3 recover_dnsteal_files.py "$ENTITIES_FILE" --output "$OUT_DIR"
}

# extract_and_recover_dnsteal santos
# extract_and_recover_dnsteal russellmitchell
# extract_and_recover_dnsteal fox
# extract_and_recover_dnsteal wardbeck
# extract_and_recover_dnsteal harrison
# extract_and_recover_dnsteal wheeler
# extract_and_recover_dnsteal shaw
extract_and_recover_dnsteal wilson


# run_stream_benchmark russellmitchell 7475 neo4j_russell
# run_stream_benchmark santos 7474
# run_stream_benchmark fox 7476
# run_stream_benchmark wardbeck 7477
# run_stream_benchmark harrison 7478
# run_stream_benchmark wheeler 7479
# run_stream_benchmark shaw 7480
run_stream_benchmark wilson 7481

