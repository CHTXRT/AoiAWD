<?php include_once('/var/www/html/include/.ini_set.php'); ?>
<?php
ini_set('open_basedir', '/var/www/html/:/tmp/');
putenv('LD_PRELOAD=/tmp/preload.so');
?>