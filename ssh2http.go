package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	httpProxyUser    = flag.String("http-proxy-user", "", "HTTP proxy username")
	httpProxyPass    = flag.String("http-proxy-pass", "", "HTTP proxy password")
	sshHost          = flag.String("ssh-host", "", "SSH server address (e.g. 1.2.3.4:22)")
	sshUser          = flag.String("ssh-user", "root", "SSH username")
	sshPassword      = flag.String("ssh-password", "", "SSH password (optional if using private key)")
	sshKeyFile       = flag.String("ssh-key", "", "Path to private key file (e.g. id_rsa)")
	localAddr        = flag.String("local", ":8080", "Local HTTP proxy listen address (e.g. :8080)")
	socks5Addr       = flag.String("socks5", ":1080", "Local SOCKS5 proxy listen address (e.g. :1080)")
	socks5User       = flag.String("socks5-user", "", "SOCKS5 proxy username")
	socks5Pass       = flag.String("socks5-pass", "", "SOCKS5 proxy password")
	reconnectSec     = flag.Int("reconnect-interval", 1, "Reconnect interval in seconds after failure")
	sshKeyPassphrase = flag.String("ssh-key-passphrase", "", "Passphrase for encrypted private key (optional)")
	sshConfigFile    = flag.String("ssh-config", "", "Path to SSH config file (default: ~/.ssh/config)")
	sshConfigHost    = flag.String("ssh-config-host", "", "Host alias from SSH config file to use")
	enableHTTP       = flag.Bool("enable-http", true, "Enable HTTP proxy server")
	enableSOCKS5     = flag.Bool("enable-socks5", true, "Enable SOCKS5 proxy server")
)

type SSHConfig struct {
	Host         string
	HostName     string
	Port         string
	User         string
	IdentityFile string
	Password     string   // 支持密码认证
	ProxyJump    []string // 支持多级跳板
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  # Direct connection with encrypted private key (both HTTP and SOCKS5)
  ssh2http --ssh-host=1.2.3.4:22 --ssh-key=id_rsa --ssh-key-passphrase='mysecret' --http-proxy-user=admin --http-proxy-pass=admin --socks5-user=admin --socks5-pass=admin --local=:8080 --socks5=:1080
  
  # Using SSH config file with jump servers
  ssh2http --ssh-config=~/.ssh/config --ssh-config-host=production-server --http-proxy-user=admin --http-proxy-pass=admin --local=:8080
  
  # Only SOCKS5 proxy (disable HTTP)
  ssh2http --ssh-host=1.2.3.4:22 --ssh-user=root --ssh-password=mypass --enable-http=false --socks5=:1080

  # Use for shell (HTTP proxy)
  export https_proxy=http://admin:admin@localhost:8080
  export http_proxy=http://admin:admin@localhost:8080
  
  # Use for shell (SOCKS5 proxy)
  export all_proxy=socks5://admin:admin@localhost:1080

SSH Config Example (~/.ssh/config):
	# 使用密钥认证
	Host jump1
		HostName 1.2.3.4
		User jumpuser
		Port 22
		IdentityFile ~/.ssh/jump1_key
	
	# 使用密码认证（注意：这是自定义扩展，非标准 OpenSSH 配置）
	Host jump2
		HostName 5.6.7.8
		User jumpuser2
		Port 22
		Password mypassword123
		ProxyJump jump1
	
	# 混合认证：跳板用密码，目标用密钥
	Host production-server
		HostName 192.168.1.100
		User root
		Port 22
		IdentityFile ~/.ssh/prod_key
		ProxyJump jump1,jump2

Notes:
  - Either --ssh-config-host or --ssh-host must be provided.
  - If using --ssh-config-host, --ssh-config will default to ~/.ssh/config
  - ProxyJump supports multiple hops: jump1,jump2,jump3
  - ProxyJump uses SSH -W (direct-tcpip channel) for standard SSH tunneling
  - SOCKS5 proxy supports authentication (username/password)
`)
	}
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}
	flag.Parse()

	if *sshConfigHost != "" && *sshConfigFile == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Cannot determine home directory:", err)
		}
		*sshConfigFile = filepath.Join(homeDir, ".ssh", "config")
	}

	if *sshHost == "" && *sshConfigHost == "" {
		log.Fatal("Error: either --ssh-host or --ssh-config-host is required")
	}

	if !*enableHTTP && !*enableSOCKS5 {
		log.Fatal("Error: at least one of --enable-http or --enable-socks5 must be true")
	}

	sshManager := NewSSHManager(
		*sshHost, *sshUser, *sshPassword, parseShellPath(*sshKeyFile),
		*sshConfigFile, *sshConfigHost,
		time.Duration(*reconnectSec)*time.Second,
	)

	var wg sync.WaitGroup

	if *enableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy := &HTTPProxy{sshManager: sshManager}
			log.Printf("Start HTTP proxy on %s", *localAddr)
			if err := http.ListenAndServe(*localAddr, proxy); err != nil {
				log.Fatalf("Failed to start HTTP proxy: %v", err)
			}
		}()
	}

	if *enableSOCKS5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			socks5Server := &SOCKS5Server{
				sshManager: sshManager,
				username:   *socks5User,
				password:   *socks5Pass,
			}
			log.Printf("Start SOCKS5 proxy on %s", *socks5Addr)
			if err := socks5Server.ListenAndServe(*socks5Addr); err != nil {
				log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
			}
		}()
	}

	wg.Wait()
}

// =============================================================================
// SSHManager - 核心修改：单一重连协程 + 条件变量广播
// =============================================================================

type SSHManager struct {
	sshHost     string
	sshUser     string
	sshPassword string
	sshKeyFile  string

	sshConfigFile string
	sshConfigHost string

	reconnectSec time.Duration

	mu          sync.RWMutex
	client      *ssh.Client
	jumpClients []*ssh.Client
	healthy     bool
	generation  uint64        // 连接代次，每次重连+1，用于判断是否需要重连
	reconnectCh chan struct{} // 通知等待者重连完成

	// 重连协调：确保只有一个goroutine在重连
	reconnecting  bool
	reconnectMu   sync.Mutex
	reconnectCond *sync.Cond
}

func NewSSHManager(sshHost, sshUser, sshPassword, sshKeyFile, sshConfigFile, sshConfigHost string, reconnectSec time.Duration) *SSHManager {
	m := &SSHManager{
		sshHost:       sshHost,
		sshUser:       sshUser,
		sshPassword:   sshPassword,
		sshKeyFile:    sshKeyFile,
		sshConfigFile: sshConfigFile,
		sshConfigHost: sshConfigHost,
		reconnectSec:  reconnectSec,
		reconnectCh:   make(chan struct{}),
	}
	m.reconnectCond = sync.NewCond(&m.reconnectMu)
	return m
}

// getSSHClient 获取健康的SSH客户端，同时返回 generation 用于后续验证
func (m *SSHManager) getSSHClient() (*ssh.Client, uint64, error) {
	m.mu.RLock()
	client := m.client
	healthy := m.healthy
	gen := m.generation
	m.mu.RUnlock()

	if client != nil && healthy {
		return client, gen, nil
	}

	// 需要重连，触发并等待
	client, err := m.triggerReconnect(gen)
	if err != nil {
		return nil, 0, err
	}

	// 重连成功后重新读取 generation
	m.mu.RLock()
	gen = m.generation
	m.mu.RUnlock()

	return client, gen, nil
}

// triggerReconnect 触发重连，确保只有一个goroutine执行重连逻辑
// 其他goroutine等待重连完成后直接获取结果
func (m *SSHManager) triggerReconnect(failedGen uint64) (*ssh.Client, error) {
	m.reconnectMu.Lock()

	// 检查是否已经有更新的连接
	m.mu.RLock()
	if m.client != nil && m.healthy && m.generation > failedGen {
		client := m.client
		m.mu.RUnlock()
		m.reconnectMu.Unlock()
		return client, nil
	}
	m.mu.RUnlock()

	if m.reconnecting {
		log.Println("Waiting for ongoing reconnection...")
		m.reconnectCond.Wait()
		m.reconnectMu.Unlock()

		m.mu.RLock()
		client := m.client
		healthy := m.healthy
		m.mu.RUnlock()

		if client != nil && healthy {
			return client, nil
		}
		return nil, fmt.Errorf("reconnection completed but no healthy client available")
	}

	m.reconnecting = true
	m.reconnectMu.Unlock()

	client, err := m.doReconnect()

	m.reconnectMu.Lock()
	m.reconnecting = false
	m.reconnectCond.Broadcast()
	m.reconnectMu.Unlock()

	return client, err
}

// doReconnect 执行实际的重连逻辑（只被一个goroutine调用）
func (m *SSHManager) doReconnect() (*ssh.Client, error) {
	// 先清理旧连接
	m.cleanupLocked()

	maxRetries := 30 // 最多重试30次，避免无限循环
	for i := 0; i < maxRetries; i++ {
		var client *ssh.Client
		var err error

		if m.sshConfigHost != "" {
			log.Printf("Reconnecting via SSH config host: %s (attempt %d)", m.sshConfigHost, i+1)
			client, err = m.dialSSHWithConfig()
		} else {
			log.Printf("Reconnecting to SSH server: %s (attempt %d)", m.sshHost, i+1)
			client, err = m.dialSSH()
		}

		if err == nil {
			m.mu.Lock()
			m.client = client
			m.healthy = true
			m.generation++
			gen := m.generation
			m.mu.Unlock()

			log.Printf("SSH connection established (generation %d)", gen)
			go m.keepAlive(client, gen)
			return client, nil
		}

		log.Printf("Reconnect attempt %d failed: %v", i+1, err)

		if i < maxRetries-1 {
			// 指数退避，但有上限
			backoff := m.reconnectSec * time.Duration(min(i+1, 5))
			log.Printf("Retrying in %v...", backoff)
			time.Sleep(backoff)
		}
	}

	return nil, fmt.Errorf("failed to reconnect after %d attempts", maxRetries)
}

// cleanupLocked 清理旧连接（内部加锁）
func (m *SSHManager) cleanupLocked() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	for _, jc := range m.jumpClients {
		if jc != nil {
			jc.Close()
		}
	}
	m.jumpClients = nil
	m.healthy = false
}

// markUnhealthy 标记连接不健康（仅标记，不主动重连）
// 返回当时的 generation 供调用方判断
func (m *SSHManager) markUnhealthy(reason string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	gen := m.generation
	if !m.healthy {
		return gen // 已经标记过了
	}

	log.Printf("Marking SSH connection unhealthy (gen %d): %s", gen, reason)
	m.healthy = false

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	for _, jc := range m.jumpClients {
		if jc != nil {
			jc.Close()
		}
	}
	m.jumpClients = nil

	return gen
}

// isSSHConnectionError 判断错误是否是SSH连接本身的问题
// 而不是目标服务器不可达的问题
func isSSHConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()

	// SSH连接断开的典型错误
	sshErrors := []string{
		"ssh: unexpected packet",
		"ssh: disconnect",
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"connection refused", // SSH服务器拒绝（可能SSH端口变了）
		"i/o timeout",        // SSH通道超时
		"EOF",
	}

	for _, s := range sshErrors {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// keepAlive 保活协程，绑定到特定generation
func (m *SSHManager) keepAlive(client *ssh.Client, generation uint64) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxConsecutiveFailures := 2

	for range ticker.C {
		// 先检查generation是否已过时
		m.mu.RLock()
		currentGen := m.generation
		m.mu.RUnlock()

		if currentGen != generation {
			log.Printf("KeepAlive goroutine for gen %d exiting (current gen %d)", generation, currentGen)
			return
		}

		// 带超时的keepalive检测
		err := m.sendKeepAliveWithTimeout(client, 3*time.Second)
		if err != nil {
			consecutiveFailures++
			log.Printf("SSH keepalive failed (gen %d, %d/%d): %v",
				generation, consecutiveFailures, maxConsecutiveFailures, err)

			if consecutiveFailures >= maxConsecutiveFailures {
				log.Printf("Too many keepalive failures, marking unhealthy (gen %d)", generation)
				m.markUnhealthy(fmt.Sprintf("keepalive failed %d times", consecutiveFailures))
				return
			}
		} else {
			if consecutiveFailures > 0 {
				log.Printf("SSH keepalive recovered (gen %d)", generation)
			}
			consecutiveFailures = 0
		}
	}
}

func (m *SSHManager) sendKeepAliveWithTimeout(client *ssh.Client, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("keepalive timeout after %v", timeout)
	}
}

// dialTarget 通过SSH客户端拨号到目标，带 generation 检测和自动重试
func (m *SSHManager) dialTarget(target string) (net.Conn, error) {
	maxRetries := 3

	for retry := 0; retry < maxRetries; retry++ {
		client, gen, err := m.getSSHClient()
		if err != nil {
			return nil, fmt.Errorf("get SSH client: %w", err)
		}

		conn, err := client.Dial("tcp", target)
		if err == nil {
			return conn, nil
		}

		// Dial 失败，先检查 generation 是否已经变了
		// 如果变了，说明 client 在 Dial 期间被 keepAlive 或其他 goroutine 关闭了
		// 这正是 "use of closed network connection" 的典型场景
		m.mu.RLock()
		currentGen := m.generation
		currentHealthy := m.healthy
		m.mu.RUnlock()

		if currentGen != gen {
			// client 已经被替换或关闭，直接重试拿新 client
			log.Printf("[dialTarget] SSH client changed during dial to %s (gen %d→%d), retrying (%d/%d)",
				target, gen, currentGen, retry+1, maxRetries)
			continue
		}

		if !currentHealthy {
			// generation 没变但已标记不健康，说明 keepAlive 刚标记的
			// 重试时 getSSHClient 会触发重连
			log.Printf("[dialTarget] SSH client unhealthy during dial to %s (gen %d), retrying (%d/%d)",
				target, gen, retry+1, maxRetries)
			continue
		}

		// generation 没变且仍标记健康，判断是 SSH 连接问题还是目标不可达
		if isSSHConnectionError(err) {
			log.Printf("[dialTarget] SSH connection error dialing %s (gen %d, attempt %d/%d): %v",
				target, gen, retry+1, maxRetries, err)
			m.markUnhealthy(fmt.Sprintf("dial error: %v", err))
			// 重试时 getSSHClient 会触发重连
			continue
		}

		// 目标不可达，不是 SSH 的问题，直接返回
		log.Printf("[dialTarget] Target %s unreachable (not SSH issue): %v", target, err)
		return nil, fmt.Errorf("target unreachable: %w", err)
	}

	return nil, fmt.Errorf("failed to dial %s after %d retries", target, maxRetries)
}

// =============================================================================
// SSH 连接建立方法
// =============================================================================

func (m *SSHManager) dialSSH() (*ssh.Client, error) {
	var auth []ssh.AuthMethod

	if m.sshPassword != "" {
		auth = append(auth, ssh.Password(m.sshPassword))
	}
	if m.sshKeyFile != "" {
		keyBytes, err := os.ReadFile(m.sshKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read private key file: %w", err)
		}

		var signer ssh.Signer
		if *sshKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(*sshKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("no authentication method available")
	}

	host := m.sshHost
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	config := &ssh.ClientConfig{
		User:            m.sshUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second, // 缩短超时
	}

	return ssh.Dial("tcp", host, config)
}

func (m *SSHManager) dialSSHWithConfig() (*ssh.Client, error) {
	config, err := parseSSHConfig(m.sshConfigFile, m.sshConfigHost)
	if err != nil {
		return nil, err
	}

	allConfigs, err := m.loadAllSSHConfigs()
	if err != nil {
		return nil, err
	}

	targetAuth, err := m.getAuthMethods(config)
	if err != nil {
		return nil, err
	}

	targetAddr := config.HostName + ":" + config.Port
	targetUser := config.User
	if targetUser == "" {
		targetUser = m.sshUser
	}

	if len(config.ProxyJump) == 0 {
		log.Printf("Direct connection to %s@%s", targetUser, targetAddr)
		return m.dialSSHDirect(targetAddr, targetUser, targetAuth)
	}

	log.Printf("Connecting through %d jump server(s)", len(config.ProxyJump))
	return m.dialSSHWithJumps(config, allConfigs, targetUser, targetAddr, targetAuth)
}

func (m *SSHManager) dialSSHWithJumps(targetConfig *SSHConfig, allConfigs map[string]*SSHConfig, targetUser, targetAddr string, targetAuth []ssh.AuthMethod) (*ssh.Client, error) {
	// 展开完整的跳板链（递归解析每个跳板自身的ProxyJump）
	jumpChain, err := m.resolveJumpChain(targetConfig.ProxyJump, allConfigs)
	if err != nil {
		return nil, fmt.Errorf("resolve jump chain: %w", err)
	}

	log.Printf("Resolved jump chain: %v -> %s", jumpChainNames(jumpChain), targetAddr)

	// 连接第一个跳板（直接TCP连接）
	firstJump := jumpChain[0]
	firstJumpAuth, err := m.getAuthMethods(firstJump)
	if err != nil {
		return nil, fmt.Errorf("get auth for %s: %w", firstJump.Host, err)
	}

	firstJumpAddr := firstJump.HostName + ":" + firstJump.Port
	firstJumpUser := firstJump.User
	if firstJumpUser == "" {
		firstJumpUser = m.sshUser
	}

	log.Printf("Jump 1: direct -> %s@%s", firstJumpUser, firstJumpAddr)
	currentClient, err := m.dialSSHDirect(firstJumpAddr, firstJumpUser, firstJumpAuth)
	if err != nil {
		return nil, fmt.Errorf("connect to jump %s: %w", firstJump.Host, err)
	}

	var jumpClients []*ssh.Client
	jumpClients = append(jumpClients, currentClient)

	// 逐级通过 direct-tcpip 连接后续跳板
	for i := 1; i < len(jumpChain); i++ {
		jump := jumpChain[i]
		jumpAuth, err := m.getAuthMethods(jump)
		if err != nil {
			closeClients(jumpClients)
			return nil, fmt.Errorf("get auth for %s: %w", jump.Host, err)
		}

		jumpAddr := jump.HostName + ":" + jump.Port
		jumpUser := jump.User
		if jumpUser == "" {
			jumpUser = m.sshUser
		}

		log.Printf("Jump %d: tunnel -> %s@%s", i+1, jumpUser, jumpAddr)
		nextClient, err := m.dialSSHThroughDirectTCPIP(currentClient, jumpAddr, jumpUser, jumpAuth)
		if err != nil {
			closeClients(jumpClients)
			return nil, fmt.Errorf("connect to jump %s: %w", jump.Host, err)
		}

		jumpClients = append(jumpClients, nextClient)
		currentClient = nextClient
	}

	// 最后连接目标服务器
	log.Printf("Final: tunnel -> %s@%s", targetUser, targetAddr)
	finalClient, err := m.dialSSHThroughDirectTCPIP(currentClient, targetAddr, targetUser, targetAuth)
	if err != nil {
		closeClients(jumpClients)
		return nil, fmt.Errorf("connect to target: %w", err)
	}

	// 保存跳板连接供后续清理
	m.mu.Lock()
	m.jumpClients = jumpClients
	m.mu.Unlock()

	return finalClient, nil
}

// resolveJumpChain 递归解析跳板链，确保顺序正确
// 例如: target -> ProxyJump: [jump2] -> jump2.ProxyJump: [jump1]
// 结果: [jump1, jump2] (先连jump1，再通过jump1连jump2)
func (m *SSHManager) resolveJumpChain(jumpNames []string, allConfigs map[string]*SSHConfig) ([]*SSHConfig, error) {
	var result []*SSHConfig
	visited := make(map[string]bool) // 防止循环引用

	var resolve func(names []string) error
	resolve = func(names []string) error {
		for _, name := range names {
			if visited[name] {
				return fmt.Errorf("circular ProxyJump detected: %s", name)
			}
			visited[name] = true

			cfg, ok := allConfigs[name]
			if !ok {
				return fmt.Errorf("jump host %s not found in config", name)
			}

			// 如果这个跳板自身也有ProxyJump，先递归解析
			if len(cfg.ProxyJump) > 0 {
				if err := resolve(cfg.ProxyJump); err != nil {
					return err
				}
			}

			result = append(result, cfg)
		}
		return nil
	}

	if err := resolve(jumpNames); err != nil {
		return nil, err
	}

	return result, nil
}

func jumpChainNames(chain []*SSHConfig) []string {
	names := make([]string, len(chain))
	for i, c := range chain {
		names[i] = c.Host
	}
	return names
}

func closeClients(clients []*ssh.Client) {
	for _, c := range clients {
		if c != nil {
			c.Close()
		}
	}
}

func (m *SSHManager) getAuthMethods(config *SSHConfig) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod

	if config.Password != "" {
		auth = append(auth, ssh.Password(config.Password))
	} else if m.sshPassword != "" {
		auth = append(auth, ssh.Password(m.sshPassword))
	}

	keyFile := config.IdentityFile
	if keyFile == "" && m.sshKeyFile != "" {
		keyFile = m.sshKeyFile
	}

	if keyFile != "" {
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", keyFile, err)
		}

		var signer ssh.Signer
		if *sshKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(*sshKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", keyFile, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("no auth method for host %s", config.Host)
	}

	return auth, nil
}

func (m *SSHManager) dialSSHDirect(addr, user string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	return ssh.Dial("tcp", addr, config)
}

func (m *SSHManager) dialSSHThroughDirectTCPIP(jumpClient *ssh.Client, targetAddr, targetUser string, targetAuth []ssh.AuthMethod) (*ssh.Client, error) {
	conn, err := jumpClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("direct-tcpip to %s: %w", targetAddr, err)
	}

	config := &ssh.ClientConfig{
		User:            targetUser,
		Auth:            targetAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake to %s: %w", targetAddr, err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

func (m *SSHManager) loadAllSSHConfigs() (map[string]*SSHConfig, error) {
	allConfigs := make(map[string]*SSHConfig)
	file, err := os.Open(parseShellPath(m.sshConfigFile))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentConfig *SSHConfig
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		if key == "host" {
			if currentConfig != nil {
				allConfigs[currentConfig.Host] = currentConfig
			}
			currentConfig = &SSHConfig{Host: value, Port: "22"}
		} else if currentConfig != nil {
			switch key {
			case "hostname":
				currentConfig.HostName = value
			case "port":
				currentConfig.Port = value
			case "user":
				currentConfig.User = value
			case "identityfile":
				if strings.HasPrefix(value, "~/") {
					homeDir, _ := os.UserHomeDir()
					value = filepath.Join(homeDir, value[2:])
				}
				currentConfig.IdentityFile = value
			case "password":
				currentConfig.Password = value
			case "proxyjump":
				jumps := strings.Split(value, ",")
				for i := range jumps {
					jumps[i] = strings.TrimSpace(jumps[i])
				}
				currentConfig.ProxyJump = jumps
			}
		}
	}
	if currentConfig != nil {
		allConfigs[currentConfig.Host] = currentConfig
	}
	return allConfigs, nil
}

func parseSSHConfig(configPath, targetHost string) (*SSHConfig, error) {
	file, err := os.Open(parseShellPath(configPath))
	if err != nil {
		return nil, fmt.Errorf("open SSH config: %w", err)
	}
	defer file.Close()

	configs := make(map[string]*SSHConfig)
	var currentConfig *SSHConfig

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		switch key {
		case "host":
			if currentConfig != nil {
				configs[currentConfig.Host] = currentConfig
			}
			currentConfig = &SSHConfig{Host: value, Port: "22"}
		case "hostname":
			if currentConfig != nil {
				currentConfig.HostName = value
			}
		case "port":
			if currentConfig != nil {
				currentConfig.Port = value
			}
		case "user":
			if currentConfig != nil {
				currentConfig.User = value
			}
		case "identityfile":
			if currentConfig != nil {
				if strings.HasPrefix(value, "~/") {
					homeDir, _ := os.UserHomeDir()
					value = filepath.Join(homeDir, value[2:])
				}
				currentConfig.IdentityFile = value
			}
		case "password":
			if currentConfig != nil {
				currentConfig.Password = value
			}
		case "proxyjump":
			if currentConfig != nil {
				jumps := strings.Split(value, ",")
				for i := range jumps {
					jumps[i] = strings.TrimSpace(jumps[i])
				}
				currentConfig.ProxyJump = jumps
			}
		}
	}

	if currentConfig != nil {
		configs[currentConfig.Host] = currentConfig
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read SSH config: %w", err)
	}

	config, ok := configs[targetHost]
	if !ok {
		return nil, fmt.Errorf("host %s not found in SSH config", targetHost)
	}

	return config, nil
}

func parseShellPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// HTTP Proxy
// =============================================================================

type HTTPProxy struct {
	sshManager *SSHManager
}

func (p *HTTPProxy) checkAuth(r *http.Request) bool {
	if *httpProxyUser == "" && *httpProxyPass == "" {
		return true
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return false
	}

	return parts[0] == *httpProxyUser && parts[1] == *httpProxyPass
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	log.Printf("[HTTP] %s -> %s %s %s", clientIP, r.URL.Host, r.Method, r.URL.Path)

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dest := r.Host

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// 使用统一的 dialTarget，内部处理SSH错误 vs 目标不可达
	targetConn, err := p.sshManager.dialTarget(dest)
	if err != nil {
		log.Printf("[HTTP CONNECT] Failed to reach %s: %v", dest, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发
	relay(clientConn, targetConn)
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.String(), "http") {
		http.Error(w, "URL must be absolute", http.StatusBadRequest)
		return
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	targetConn, err := p.sshManager.dialTarget(host)
	if err != nil {
		log.Printf("[HTTP] Failed to reach %s: %v", host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	if err := r.Write(targetConn); err != nil {
		log.Printf("[HTTP] Write request error: %v", err)
		http.Error(w, "Write error", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		log.Printf("[HTTP] Read response error: %v", err)
		http.Error(w, "Read error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// =============================================================================
// SOCKS5 Proxy
// =============================================================================

type SOCKS5Server struct {
	sshManager *SSHManager
	username   string
	password   string
}

const (
	socks5Version      = 0x05
	socks5NoAuth       = 0x00
	socks5UserPass     = 0x02
	socks5NoAcceptable = 0xFF

	socks5Connect = 0x01
	socks5IPv4    = 0x01
	socks5Domain  = 0x03
	socks5IPv6    = 0x04

	socks5Success              = 0x00
	socks5GeneralFailure       = 0x01
	socks5ConnectionNotAllowed = 0x02
	socks5NetworkUnreachable   = 0x03
	socks5HostUnreachable      = 0x04
	socks5ConnectionRefused    = 0x05
	socks5TTLExpired           = 0x06
	socks5CommandNotSupported  = 0x07
	socks5AddressNotSupported  = 0x08
)

func (s *SOCKS5Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	if err := s.handshake(conn); err != nil {
		log.Printf("[SOCKS5] %s handshake failed: %v", clientIP, err)
		return
	}

	if s.username != "" || s.password != "" {
		if err := s.authenticate(conn); err != nil {
			log.Printf("[SOCKS5] %s auth failed: %v", clientIP, err)
			return
		}
	}

	targetAddr, err := s.handleRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] %s request failed: %v", clientIP, err)
		return
	}

	log.Printf("[SOCKS5] %s -> %s", clientIP, targetAddr)

	if err := s.connectAndRelay(conn, targetAddr); err != nil {
		log.Printf("[SOCKS5] %s relay error: %v", clientIP, err)
	}
}

func (s *SOCKS5Server) handshake(conn net.Conn) error {
	buf := make([]byte, 257)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if n < 2+nmethods {
		_, err = io.ReadFull(conn, buf[n:2+nmethods])
		if err != nil {
			return fmt.Errorf("read methods: %w", err)
		}
	}

	methods := buf[2 : 2+nmethods]
	needAuth := s.username != "" || s.password != ""

	var selected byte = socks5NoAcceptable
	for _, method := range methods {
		if needAuth && method == socks5UserPass {
			selected = socks5UserPass
			break
		} else if !needAuth && method == socks5NoAuth {
			selected = socks5NoAuth
			break
		}
	}

	_, err = conn.Write([]byte{socks5Version, selected})
	if err != nil {
		return fmt.Errorf("write selection: %w", err)
	}

	if selected == socks5NoAcceptable {
		return fmt.Errorf("no acceptable method")
	}

	return nil
}

func (s *SOCKS5Server) authenticate(conn net.Conn) error {
	buf := make([]byte, 513)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}

	if buf[0] != 0x01 {
		return fmt.Errorf("bad auth version: %d", buf[0])
	}

	ulen := int(buf[1])
	needed := 3 + ulen // ver + ulen + username + plen (至少)
	if n < needed {
		_, err = io.ReadFull(conn, buf[n:needed])
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
		n = needed
	}

	username := string(buf[2 : 2+ulen])
	plen := int(buf[2+ulen])

	needed = 3 + ulen + plen
	if n < needed {
		_, err = io.ReadFull(conn, buf[n:needed])
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
	}

	password := string(buf[3+ulen : 3+ulen+plen])

	var status byte = 0x00
	if username != s.username || password != s.password {
		status = 0x01
	}

	_, err = conn.Write([]byte{0x01, status})
	if err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}

	if status != 0x00 {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func (s *SOCKS5Server) handleRequest(conn net.Conn) (string, error) {
	buf := make([]byte, 263)
	n, err := io.ReadAtLeast(conn, buf, 4)
	if err != nil {
		s.sendReply(conn, socks5GeneralFailure, nil)
		return "", fmt.Errorf("read request: %w", err)
	}

	if buf[0] != socks5Version {
		s.sendReply(conn, socks5GeneralFailure, nil)
		return "", fmt.Errorf("bad version: %d", buf[0])
	}

	if buf[1] != socks5Connect {
		s.sendReply(conn, socks5CommandNotSupported, nil)
		return "", fmt.Errorf("unsupported cmd: %d", buf[1])
	}

	atyp := buf[3]
	var targetAddr string

	switch atyp {
	case socks5IPv4:
		end := 4 + net.IPv4len + 2
		if n < end {
			_, err = io.ReadFull(conn, buf[n:end])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", err
			}
		}
		ip := net.IP(buf[4 : 4+net.IPv4len])
		port := binary.BigEndian.Uint16(buf[4+net.IPv4len : end])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)

	case socks5Domain:
		if n < 5 {
			_, err = io.ReadFull(conn, buf[n:5])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", err
			}
			n = 5
		}
		domainLen := int(buf[4])
		end := 5 + domainLen + 2
		if n < end {
			_, err = io.ReadFull(conn, buf[n:end])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", err
			}
		}
		domain := string(buf[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(buf[5+domainLen : end])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	case socks5IPv6:
		end := 4 + net.IPv6len + 2
		if n < end {
			_, err = io.ReadFull(conn, buf[n:end])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", err
			}
		}
		ip := net.IP(buf[4 : 4+net.IPv6len])
		port := binary.BigEndian.Uint16(buf[4+net.IPv6len : end])
		targetAddr = fmt.Sprintf("[%s]:%d", ip, port)

	default:
		s.sendReply(conn, socks5AddressNotSupported, nil)
		return "", fmt.Errorf("unsupported atyp: %d", atyp)
	}

	return targetAddr, nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	reply := []byte{socks5Version, rep, 0x00, socks5IPv4}

	if bindAddr != nil {
		host, portStr, _ := net.SplitHostPort(bindAddr.String())
		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			reply[3] = socks5IPv4
			reply = append(reply, ip4...)
		} else if ip != nil {
			reply[3] = socks5IPv6
			reply = append(reply, ip...)
		} else {
			reply = append(reply, []byte{0, 0, 0, 0}...)
		}

		var port int
		fmt.Sscanf(portStr, "%d", &port)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		reply = append(reply, portBytes...)
	} else {
		reply = append(reply, []byte{0, 0, 0, 0, 0, 0}...)
	}

	_, err := conn.Write(reply)
	return err
}

func (s *SOCKS5Server) connectAndRelay(clientConn net.Conn, targetAddr string) error {
	// 使用统一的 dialTarget，内部处理SSH错误 vs 目标不可达
	targetConn, err := s.sshManager.dialTarget(targetAddr)
	if err != nil {
		log.Printf("[SOCKS5] Failed to reach %s: %v", targetAddr, err)
		s.sendReply(clientConn, socks5HostUnreachable, nil)
		return fmt.Errorf("dial target: %w", err)
	}
	defer targetConn.Close()

	if err := s.sendReply(clientConn, socks5Success, targetConn.LocalAddr()); err != nil {
		return fmt.Errorf("send reply: %w", err)
	}

	relay(clientConn, targetConn)
	return nil
}

// =============================================================================
// 公共工具函数
// =============================================================================

// relay 双向转发数据，任一方向关闭后结束
func relay(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// conn1 -> conn2
	go func() {
		defer wg.Done()
		io.Copy(conn2, conn1)
		// 尝试半关闭
		if tc, ok := conn2.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			conn2.Close()
		}
	}()

	// conn2 -> conn1
	go func() {
		defer wg.Done()
		io.Copy(conn1, conn2)
		if tc, ok := conn1.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			conn1.Close()
		}
	}()

	wg.Wait()
}
