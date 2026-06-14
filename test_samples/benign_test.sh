#!/bin/bash
# 测试样本：创建文件 + 拉起子进程 + 发起网络连接
set +e

OUTPUT_DIR="/tmp/sample_output_$$"
mkdir -p "$OUTPUT_DIR"

echo "[SAMPLE] Starting at $(date)"
echo "[SAMPLE] PID: $$"
echo "[SAMPLE] PPID: $PPID"

# ========== 1. 文件系统操作 ==========
echo "[SAMPLE] --- File Operations ---"

# 创建多个文件
echo "malware config data" > "$OUTPUT_DIR/config.dat"
echo "stolen password 12345" > "$OUTPUT_DIR/credentials.txt"
echo "temp data" > "/tmp/tmpfile_$$.tmp"

# 修改文件
echo "additional stolen data" >> "$OUTPUT_DIR/credentials.txt"
echo "updated config" >> "$OUTPUT_DIR/config.dat"

# 创建子目录并写文件
mkdir -p "$OUTPUT_DIR/subdir"
for i in 1 2 3; do
    echo "payload part $i" > "$OUTPUT_DIR/subdir/payload_$i.bin"
done

echo "[SAMPLE] Created files in $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

# ========== 2. 拉起子进程 ==========
echo "[SAMPLE] --- Process Operations ---"

# 启动多个子进程
echo "[SAMPLE] Launching child processes..."

# 子进程 1：sleep 模拟后台任务
sleep 30 &
CHILD1=$!
echo "[SAMPLE] Launched child1 (sleep, PID=$CHILD1)"

# 子进程 2：执行 ls 命令
ls -la /tmp > "$OUTPUT_DIR/ls_output.txt" 2>&1 &
CHILD2=$!
echo "[SAMPLE] Launched child2 (ls, PID=$CHILD2)"

# 子进程 3：执行 whoami
whoami > "$OUTPUT_DIR/whoami.txt" 2>&1 &
CHILD3=$!
echo "[SAMPLE] Launched child3 (whoami, PID=$CHILD3)"

# 子进程 4：执行 cat 读取敏感文件
cat /etc/passwd > "$OUTPUT_DIR/passwd_copy.txt" 2>&1 &
CHILD4=$!
echo "[SAMPLE] Launched child4 (cat /etc/passwd, PID=$CHILD4)"

# 子进程 5：递归型（创建更多子进程）
bash -c "
    sleep 5 &
    SP1=\$!
    echo \"[GRANDCHILD] spawned by \$\$: sleep PID=\$SP1\"
    echo \"grandchild activity\" > /tmp/grandchild_$$.txt
    wait \$SP1
" &
CHILD5=$!
echo "[SAMPLE] Launched child5 (spawns grandchild, PID=$CHILD5)"

# 等待部分子进程完成
wait $CHILD2 $CHILD3 $CHILD4 2>/dev/null || true
echo "[SAMPLE] Some children completed"

# ========== 3. 网络连接 ==========
echo "[SAMPLE] --- Network Operations ---"

# 尝试 DNS 查询
if command -v getent >/dev/null 2>&1; then
    echo "[SAMPLE] DNS lookup for google.com..."
    getent hosts google.com > "$OUTPUT_DIR/dns_result.txt" 2>&1 || true
fi

# 尝试通过 /dev/tcp 发起连接（bash built-in）
if command -v bash >/dev/null 2>&1; then
    echo "[SAMPLE] Attempting TCP connections..."
    for host_port in "google.com:80" "example.com:443" "8.8.8.8:53"; do
        host="${host_port%%:*}"
        port="${host_port##*:}"
        (echo -n "GET / HTTP/1.0\r\nHost: $host\r\n\r\n" > /dev/tcp/$host/$port) > "$OUTPUT_DIR/conn_${host}_${port}.txt" 2>&1 &
        NET_PID=$!
        echo "[SAMPLE] Connection attempt to $host:$port (PID=$NET_PID)"
        sleep 1
        kill $NET_PID 2>/dev/null || true
    done
fi

# 尝试 wget/curl
if command -v wget >/dev/null 2>&1; then
    echo "[SAMPLE] wget attempt..."
    timeout 5 wget -q -O "$OUTPUT_DIR/wget_result.html" http://example.com/ > "$OUTPUT_DIR/wget_log.txt" 2>&1 || true
elif command -v curl >/dev/null 2>&1; then
    echo "[SAMPLE] curl attempt..."
    timeout 5 curl -s -o "$OUTPUT_DIR/curl_result.html" http://example.com/ > "$OUTPUT_DIR/curl_log.txt" 2>&1 || true
fi

# 创建网络相关的临时文件
echo "C2 server: c2.malware-domain.com:443" > "$OUTPUT_DIR/c2_config.txt"
echo "exfil target: 192.168.1.100:8080" >> "$OUTPUT_DIR/c2_config.txt"

# ========== 4. 更多文件操作（删改） ==========
echo "[SAMPLE] --- More File Ops ---"

# 删除临时文件
rm -f "/tmp/tmpfile_$$.tmp"
echo "[SAMPLE] Deleted temp file"

# 重命名/移动文件
mv "$OUTPUT_DIR/config.dat" "$OUTPUT_DIR/config_v2.dat" 2>/dev/null || true
echo "[SAMPLE] Renamed config.dat -> config_v2.dat"

# 再次修改 credentials
echo "exfiltrated at $(date)" >> "$OUTPUT_DIR/credentials.txt"

# ========== 等待结束 ==========
echo "[SAMPLE] Waiting for remaining children (with timeout)..."
sleep 5

# 清理后台子进程（模拟恶意软件退出）
kill $CHILD1 $CHILD5 2>/dev/null || true
sleep 1

echo "[SAMPLE] All done at $(date)"
echo "[SAMPLE] Final directory listing:"
find "$OUTPUT_DIR" -type f 2>/dev/null

exit 0
