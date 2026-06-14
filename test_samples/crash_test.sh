#!/bin/bash
# 异常退出样本：快速崩溃，不产生有效行为日志
set +e

echo "[CRASHER] About to crash..."
echo "[CRASHER] PID=$$"

# 快速触发异常退出
kill -9 $$

# 以下代码不会被执行
echo "should not reach here"
mkdir -p /tmp/should_not_exist
echo "data" > /tmp/should_not_exist/data.txt

exit 0
