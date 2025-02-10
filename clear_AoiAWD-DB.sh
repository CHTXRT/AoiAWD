docker cp clear-mongoDB.js aoiawd-mongodb-1:/
docker exec aoiawd-mongodb-1 mongosh --file /clear-mongoDB.js