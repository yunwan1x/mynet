#!/bin/bash
# test_ssh2http.sh - SSH代理核心场景测试
#
# 使用: chmod +x test_ssh2http.sh && ./test_ssh2http.sh

# =============================================================================
# 配置区域 - 根据实际环境修改
# =============================================================================

BINARY="./ssh2http"

# 场景1: 直连 - 用户名密码
SSH_HOST="8.210.191.242:22"
SSH_USER="root"
SSH_PASSWORD="FqfB*XecY8mb9"

# 场景2: 直连 - 密钥
SSH_KEY="~/.ssh/id_rsa"
SSH_KEY_PASSPHRASE=""          # 加密密钥填密码，否则留空

# 场景3: SSH Config 直连
SSH_CONFIG="~/.ssh/config"
SSH_CONFIG_HOST="xianggang"    # ssh config 中的 Host 别名

# 场景4: SSH Config + JumpServer
SSH_CONFIG_JUMP_HOST="122a10"  # ssh config 中带 ProxyJump 的 Host

# 代理端口和认证
HTTP_PORT=18080
SOCKS5_PORT=11080
PROXY_USER="admin"
PROXY_PASS="admin123"

# 测试目标
TEST_URL_HTTP="http://httpbin.org/ip"
TEST_URL_HTTPS="https://httpbin.org/ip"

# =============================================================================
# 工具函数
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0
PROXY_PID=""
LOG_FILE="/tmp/ssh2http_test_$$.log"

run_test() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    printf "  %-55s " "$name"

    output=$(eval "$@" 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
        [ -n "$output" ] && echo "$output" | head -3 | sed 's/^/      /'
    fi
}

stop_proxy() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null && wait "$PROXY_PID" 2>/dev/null
    PROXY_PID=""
    sleep 1
}

start_proxy() {
    stop_proxy
    local cmd="$1"
    echo -e "\n  ${YELLOW}启动代理:${NC} $cmd"
    eval "$cmd" > "$LOG_FILE" 2>&1 &
    PROXY_PID=$!

    # 等待端口就绪
    for i in $(seq 1 20); do
        if nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null && \
           nc -z 127.0.0.1 "$SOCKS5_PORT" 2>/dev/null; then
            echo -e "  ${GREEN}代理已启动${NC} (PID: $PROXY_PID)"
            return 0
        fi
        sleep 1
    done
    echo -e "  ${RED}代理启动失败${NC}"
    tail -5 "$LOG_FILE" | sed 's/^/      /'
    stop_proxy
    return 1
}

test_http_proxy() {
    run_test "HTTP代理 - HTTP请求" '
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proxy "http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${HTTP_PORT}" \
            --connect-timeout 10 --max-time 15 \
            "$TEST_URL_HTTP")
        [ "$code" = "200" ]
    '

    run_test "HTTP代理 - HTTPS请求(CONNECT)" '
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proxy "http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${HTTP_PORT}" \
            --connect-timeout 10 --max-time 15 \
            "$TEST_URL_HTTPS")
        [ "$code" = "200" ]
    '
}

test_socks5_proxy() {
    run_test "SOCKS5代理 - HTTP请求" '
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --socks5-hostname "${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${SOCKS5_PORT}" \
            --connect-timeout 10 --max-time 15 \
            "$TEST_URL_HTTP")
        [ "$code" = "200" ]
    '

    run_test "SOCKS5代理 - HTTPS请求" '
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --socks5-hostname "${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${SOCKS5_PORT}" \
            --connect-timeout 10 --max-time 15 \
            "$TEST_URL_HTTPS")
        [ "$code" = "200" ]
    '
}

cleanup() {
    stop_proxy
    rm -f "$LOG_FILE"
}
trap cleanup EXIT INT TERM

# =============================================================================
# 主流程
# =============================================================================

echo -e "${BOLD}"
echo "╔════════════════════════════════════════╗"
echo "║     SSH2HTTP 核心场景测试              ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# 编译
if [ ! -x "$BINARY" ]; then
    echo -e "${YELLOW}编译中...${NC}"
    go build  -o "$BINARY" ssh2http.go || { echo -e "${RED}编译失败${NC}"; exit 1; }
fi

# ─────────────────────────────────────────────
echo -e "\n${BOLD}═══ 场景1: 直连SSH - 用户名密码 ═══${NC}"
# ─────────────────────────────────────────────

start_proxy "${BINARY} \
    --ssh-host=${SSH_HOST} \
    --ssh-user=${SSH_USER} \
    --ssh-password=${SSH_PASSWORD} \
    --http-proxy-user=${PROXY_USER} \
    --http-proxy-pass=${PROXY_PASS} \
    --socks5-user=${PROXY_USER} \
    --socks5-pass=${PROXY_PASS} \
    --local=:${HTTP_PORT} \
    --socks5=:${SOCKS5_PORT} \
    --reconnect-interval=2" && {
    test_http_proxy
    test_socks5_proxy
}

# ─────────────────────────────────────────────
echo -e "\n${BOLD}═══ 场景2: 直连SSH - 密钥认证 ═══${NC}"
# ─────────────────────────────────────────────

KEY_ARGS="--ssh-key=${SSH_KEY}"
[ -n "$SSH_KEY_PASSPHRASE" ] && KEY_ARGS+=" --ssh-key-passphrase=${SSH_KEY_PASSPHRASE}"

start_proxy "${BINARY} \
    --ssh-host=${SSH_HOST} \
    --ssh-user=${SSH_USER} \
    ${KEY_ARGS} \
    --http-proxy-user=${PROXY_USER} \
    --http-proxy-pass=${PROXY_PASS} \
    --socks5-user=${PROXY_USER} \
    --socks5-pass=${PROXY_PASS} \
    --local=:${HTTP_PORT} \
    --socks5=:${SOCKS5_PORT} \
    --reconnect-interval=2" && {
    test_http_proxy
    test_socks5_proxy
}

# ─────────────────────────────────────────────
echo -e "\n${BOLD}═══ 场景3: SSH Config 直连 ═══${NC}"
# ─────────────────────────────────────────────

if [ -n "$SSH_CONFIG_HOST" ] && [ -f "$(eval echo $SSH_CONFIG)" ]; then
    start_proxy "${BINARY} \
        --ssh-config=${SSH_CONFIG} \
        --ssh-config-host=${SSH_CONFIG_HOST} \
        --http-proxy-user=${PROXY_USER} \
        --http-proxy-pass=${PROXY_PASS} \
        --socks5-user=${PROXY_USER} \
        --socks5-pass=${PROXY_PASS} \
        --local=:${HTTP_PORT} \
        --socks5=:${SOCKS5_PORT} \
        --reconnect-interval=2" && {
        test_http_proxy
        test_socks5_proxy
    }
else
    echo -e "  ${YELLOW}跳过: SSH_CONFIG_HOST 或配置文件未设置${NC}"
fi

# ─────────────────────────────────────────────
echo -e "\n${BOLD}═══ 场景4: SSH Config + JumpServer ═══${NC}"
# ─────────────────────────────────────────────

if [ -n "$SSH_CONFIG_JUMP_HOST" ] && [ -f "$(eval echo $SSH_CONFIG)" ]; then
    start_proxy "${BINARY} \
        --ssh-config=${SSH_CONFIG} \
        --ssh-config-host=${SSH_CONFIG_JUMP_HOST} \
        --http-proxy-user=${PROXY_USER} \
        --http-proxy-pass=${PROXY_PASS} \
        --socks5-user=${PROXY_USER} \
        --socks5-pass=${PROXY_PASS} \
        --local=:${HTTP_PORT} \
        --socks5=:${SOCKS5_PORT} \
        --reconnect-interval=2" && {
        test_http_proxy
        test_socks5_proxy
    }
else
    echo -e "  ${YELLOW}跳过: SSH_CONFIG_JUMP_HOST 未设置${NC}"
fi

# ─────────────────────────────────────────────
echo -e "\n${BOLD}═══ 场景5: 错误恢复 ═══${NC}"
# ─────────────────────────────────────────────

# 用场景1的配置重新启动
start_proxy "${BINARY} \
    --ssh-host=${SSH_HOST} \
    --ssh-user=${SSH_USER} \
    --ssh-password=${SSH_PASSWORD} \
    --http-proxy-user=${PROXY_USER} \
    --http-proxy-pass=${PROXY_PASS} \
    --socks5-user=${PROXY_USER} \
    --socks5-pass=${PROXY_PASS} \
    --local=:${HTTP_PORT} \
    --socks5=:${SOCKS5_PORT} \
    --reconnect-interval=2" && {

    run_test "不可达目标不影响代理" '
        # 请求不可达地址
        curl -s --proxy "http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${HTTP_PORT}" \
            --connect-timeout 5 --max-time 8 \
            "http://192.0.2.1:12345/" >/dev/null 2>&1 || true
        sleep 1
        # 正常请求仍然成功
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proxy "http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${HTTP_PORT}" \
            --connect-timeout 10 --max-time 15 \
            "$TEST_URL_HTTP")
        [ "$code" = "200" ]
    '

    run_test "5个并发请求全部成功" '
        tmpdir=$(mktemp -d)
        for i in $(seq 1 5); do
            (
                code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --proxy "http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${HTTP_PORT}" \
                    --connect-timeout 10 --max-time 15 \
                    "$TEST_URL_HTTP")
                echo "$code" > "$tmpdir/$i"
            ) &
        done
        wait
        fail=0
        for i in $(seq 1 5); do
            [ "$(cat $tmpdir/$i)" != "200" ] && fail=$((fail+1))
        done
        rm -rf "$tmpdir"
        [ "$fail" -eq 0 ]
    '
}

# =============================================================================
# 测试报告
# =============================================================================

echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "  总计: ${TOTAL}  ${GREEN}通过: ${PASS}${NC}  ${RED}失败: ${FAIL}${NC}"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✓ 全部通过${NC}"
else
    echo -e "  ${RED}${BOLD}✗ 有失败项${NC}"
    echo -e "\n  代理日志 (最后10行):"
    tail -10 "$LOG_FILE" 2>/dev/null | sed 's/^/    /'
fi
echo -e "${BOLD}════════════════════════════════════════${NC}"

[ "$FAIL" -eq 0 ]
