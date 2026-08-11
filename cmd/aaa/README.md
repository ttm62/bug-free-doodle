# russell
go run ./cmd/aaa/*.go -mode neo4j -folder russell_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7474
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file russell_alerts.jsonl -neo4j-url http://localhost:7474

# santos
go run ./cmd/aaa/*.go -mode neo4j -folder santos_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7475
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file santos_alerts.jsonl -neo4j-url http://localhost:7475

# fox
go run ./cmd/aaa/*.go -mode neo4j -folder fox_no-pcaps -neo4j-user "neo4j" -neo4j-pass "admin1234" -neo4j-url http://localhost:7476
go run ./cmd/aaa/*.go -mode detect -rules ./all_rules -alerts-file fox_alerts.jsonl -neo4j-url http://localhost:7476
