cd `dirname $0`
# pwd
docker-compose up -d --build
docker logs aoiawd-aoiawd-1

docker exec aoiawd-aoiawd-1 apt-get update
docker exec aoiawd-aoiawd-1 apt-get install -y libinotifytools0-dev
docker exec -w /usr/src/TapeWorm aoiawd-aoiawd-1 php compile.php
docker exec -w /usr/src/RoundWorm aoiawd-aoiawd-1 make
docker exec -w /usr/src/Guardian aoiawd-aoiawd-1 php compile.php

echo ""
docker cp aoiawd-aoiawd-1:/usr/src/TapeWorm/tapeworm.phar .
echo "tapeworm.phar 已复制到项目目录"
docker cp aoiawd-aoiawd-1:/usr/src/RoundWorm/roundworm .
echo "roundworm 已复制到项目目录"
docker cp aoiawd-aoiawd-1:/usr/src/Guardian/guardian.phar .
echo "guardian.phar 已复制到项目目录"
echo ""