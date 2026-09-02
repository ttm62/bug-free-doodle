docker-compose up -d neo4j_santos
docker-compose up -d neo4j_russell
docker-compose up -d neo4j_fox
docker-compose up -d neo4j_wardbeck
docker-compose up -d neo4j_harrison

docker-compose up -d

docker-compose stop neo4j_santos
docker-compose stop neo4j_russell
docker-compose stop neo4j_fox
docker-compose stop neo4j_wardbeck
docker-compose stop neo4j_harrison

docker-compose down

docker ps
