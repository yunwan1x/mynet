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
	//添加http代理的账密
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
	reconnectSec     = flag.Int("reconnect-interval", 5, "Reconnect interval in seconds after failure")
	sshKeyPassphrase = flag.String("ssh-key-passphrase", "", "Passphrase for encrypted private key (optional)")
	sshConfigFile    = flag.String("ssh-config", "", "Path to SSH config file (default: ~/.ssh/config)")
	sshConfigHost    = flag.String("ssh-config-host", "", "Host alias from SSH config file to use")
	enableHTTP       = flag.Bool("enable-http", true, "Enable HTTP proxy server")
	enableSOCKS5     = flag.Bool("enable-socks5", true, "Enable SOCKS5 proxy server")
)

// SSHConfig 存储从 ssh_config 解析的配置
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

	// 如果使用 ssh-config-host 但没指定 ssh-config，使用默认路径
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

	// 创建共享的 SSH 连接管理器
	sshManager := &SSHManager{
		sshHost:       *sshHost,
		sshUser:       *sshUser,
		sshPassword:   *sshPassword,
		sshKeyFile:    parseShellPath(*sshKeyFile),
		reconnectSec:  time.Duration(*reconnectSec) * time.Second,
		sshConfigFile: *sshConfigFile,
		sshConfigHost: *sshConfigHost,
	}

	var wg sync.WaitGroup

	// 启动 HTTP 代理服务器
	if *enableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy := &HTTPProxy{sshManager: sshManager}
			log.Printf("Starting HTTP proxy on %s", *localAddr)
			if *sshConfigHost != "" {
				log.Printf("Using SSH config host: %s from %s", *sshConfigHost, *sshConfigFile)
			} else {
				log.Printf("Direct connection to SSH server: %s", *sshHost)
			}
			err := http.ListenAndServe(*localAddr, proxy)
			if err != nil {
				log.Fatalf("Failed to start HTTP proxy: %v", err)
			}
		}()
	}

	// 启动 SOCKS5 代理服务器
	if *enableSOCKS5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			socks5Server := &SOCKS5Server{
				sshManager: sshManager,
				username:   *socks5User,
				password:   *socks5Pass,
			}
			log.Printf("Starting SOCKS5 proxy on %s", *socks5Addr)
			err := socks5Server.ListenAndServe(*socks5Addr)
			if err != nil {
				log.Fatalf("Failed to start SOCKS5 proxy: %v", err)
			}
		}()
	}

	wg.Wait()
}

// SSHManager 管理 SSH 连接（HTTP 和 SOCKS5 共享）
type SSHManager struct {
	sshHost     string
	sshUser     string
	sshPassword string
	sshKeyFile  string

	sshConfigFile string
	sshConfigHost string

	reconnectSec time.Duration

	mu            sync.RWMutex
	client        *ssh.Client
	jumpClients   []*ssh.Client // 保存跳板机连接链
	lastError     error
	clientHealthy bool
}

// HTTPProxy 实现 http.Handler，作为 HTTP 代理
type HTTPProxy struct {
	sshManager *SSHManager
}

// SOCKS5Server SOCKS5 代理服务器
type SOCKS5Server struct {
	sshManager *SSHManager
	username   string
	password   string
}

// SOCKS5 常量
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

// ListenAndServe 启动 SOCKS5 服务器
func (s *SOCKS5Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SOCKS5 accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 1. 握手阶段 - 协商认证方法
	if err := s.handshake(conn); err != nil {
		log.Printf("[SOCKS5] Client %s handshake failed: %v", clientIP, err)
		return
	}

	// 2. 认证阶段（如果需要）
	if s.username != "" || s.password != "" {
		if err := s.authenticate(conn); err != nil {
			log.Printf("[SOCKS5] Client %s authentication failed: %v", clientIP, err)
			return
		}
	}

	// 3. 请求阶段
	targetAddr, err := s.handleRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] Client %s request failed: %v", clientIP, err)
		return
	}

	log.Printf("[SOCKS5] Client %s -> Target %s", clientIP, targetAddr)

	// 4. 连接目标服务器
	if err := s.connectAndRelay(conn, targetAddr); err != nil {
		log.Printf("[SOCKS5] Client %s relay error: %v", clientIP, err)
	}
}

func (s *SOCKS5Server) handshake(conn net.Conn) error {
	// 读取客户端支持的认证方法
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	buf := make([]byte, 257)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if n < 2+nmethods {
		_, err = io.ReadFull(conn, buf[n:2+nmethods])
		if err != nil {
			return fmt.Errorf("read methods: %w", err)
		}
	}

	methods := buf[2 : 2+nmethods]

	// 选择认证方法
	var selectedMethod byte = socks5NoAcceptable
	needAuth := s.username != "" || s.password != ""

	for _, method := range methods {
		if needAuth && method == socks5UserPass {
			selectedMethod = socks5UserPass
			break
		} else if !needAuth && method == socks5NoAuth {
			selectedMethod = socks5NoAuth
			break
		}
	}

	// 发送选择的认证方法
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	_, err = conn.Write([]byte{socks5Version, selectedMethod})
	if err != nil {
		return fmt.Errorf("write method selection: %w", err)
	}

	if selectedMethod == socks5NoAcceptable {
		return fmt.Errorf("no acceptable authentication method")
	}

	return nil
}

func (s *SOCKS5Server) authenticate(conn net.Conn) error {
	// 用户名/密码认证
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	buf := make([]byte, 513)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}

	if buf[0] != 0x01 { // 用户名/密码认证版本
		return fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	ulen := int(buf[1])
	if n < 2+ulen {
		_, err = io.ReadFull(conn, buf[n:2+ulen])
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
		n = 2 + ulen
	}

	username := string(buf[2 : 2+ulen])

	if n < 3+ulen {
		_, err = io.ReadFull(conn, buf[n:3+ulen])
		if err != nil {
			return fmt.Errorf("read password length: %w", err)
		}
		n = 3 + ulen
	}

	plen := int(buf[2+ulen])
	if n < 3+ulen+plen {
		_, err = io.ReadFull(conn, buf[n:3+ulen+plen])
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
	}

	password := string(buf[3+ulen : 3+ulen+plen])

	// 验证用户名和密码
	// +----+--------+
	// |VER | STATUS |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	var status byte = 0x00 // 成功
	if username != s.username || password != s.password {
		status = 0x01 // 失败
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
	// 读取客户端请求
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	buf := make([]byte, 263)
	n, err := io.ReadAtLeast(conn, buf, 4)
	if err != nil {
		s.sendReply(conn, socks5GeneralFailure, nil)
		return "", fmt.Errorf("read request header: %w", err)
	}

	if buf[0] != socks5Version {
		s.sendReply(conn, socks5GeneralFailure, nil)
		return "", fmt.Errorf("unsupported version: %d", buf[0])
	}

	cmd := buf[1]
	if cmd != socks5Connect {
		s.sendReply(conn, socks5CommandNotSupported, nil)
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := buf[3]
	var targetAddr string

	switch atyp {
	case socks5IPv4:
		// IPv4 地址：4 字节
		if n < 4+net.IPv4len {
			_, err = io.ReadFull(conn, buf[n:4+net.IPv4len])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read IPv4: %w", err)
			}
			n = 4 + net.IPv4len
		}
		ip := net.IP(buf[4 : 4+net.IPv4len])

		if n < 4+net.IPv4len+2 {
			_, err = io.ReadFull(conn, buf[n:4+net.IPv4len+2])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read port: %w", err)
			}
		}
		port := binary.BigEndian.Uint16(buf[4+net.IPv4len : 4+net.IPv4len+2])
		targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)

	case socks5Domain:
		// 域名：1 字节长度 + 域名
		if n < 5 {
			_, err = io.ReadFull(conn, buf[n:5])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read domain length: %w", err)
			}
			n = 5
		}
		domainLen := int(buf[4])

		if n < 5+domainLen {
			_, err = io.ReadFull(conn, buf[n:5+domainLen])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read domain: %w", err)
			}
			n = 5 + domainLen
		}
		domain := string(buf[5 : 5+domainLen])

		if n < 5+domainLen+2 {
			_, err = io.ReadFull(conn, buf[n:5+domainLen+2])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read port: %w", err)
			}
		}
		port := binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	case socks5IPv6:
		// IPv6 地址：16 字节
		if n < 4+net.IPv6len {
			_, err = io.ReadFull(conn, buf[n:4+net.IPv6len])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read IPv6: %w", err)
			}
			n = 4 + net.IPv6len
		}
		ip := net.IP(buf[4 : 4+net.IPv6len])

		if n < 4+net.IPv6len+2 {
			_, err = io.ReadFull(conn, buf[n:4+net.IPv6len+2])
			if err != nil {
				s.sendReply(conn, socks5GeneralFailure, nil)
				return "", fmt.Errorf("read port: %w", err)
			}
		}
		port := binary.BigEndian.Uint16(buf[4+net.IPv6len : 4+net.IPv6len+2])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)

	default:
		s.sendReply(conn, socks5AddressNotSupported, nil)
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	return targetAddr, nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	reply := []byte{socks5Version, rep, 0x00, 0x01}

	if bindAddr != nil {
		// 如果有绑定地址，使用它
		host, portStr, _ := net.SplitHostPort(bindAddr.String())
		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			reply[3] = socks5IPv4
			reply = append(reply, ip4...)
		} else {
			reply[3] = socks5IPv6
			reply = append(reply, ip...)
		}

		port := 0
		fmt.Sscanf(portStr, "%d", &port)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		reply = append(reply, portBytes...)
	} else {
		// 使用默认值 0.0.0.0:0
		reply = append(reply, []byte{0, 0, 0, 0, 0, 0}...)
	}

	_, err := conn.Write(reply)
	return err
}

func (s *SOCKS5Server) connectAndRelay(clientConn net.Conn, targetAddr string) error {
	maxRetries := 3
	var sshClient *ssh.Client
	var targetConn net.Conn
	var err error

	for retry := 0; retry < maxRetries; retry++ {
		sshClient, err = s.sshManager.getSSHClient()
		if err != nil {
			log.Printf("Failed to get SSH client for SOCKS5 (attempt %d/%d): %v", retry+1, maxRetries, err)
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			s.sendReply(clientConn, socks5GeneralFailure, nil)
			return fmt.Errorf("SSH unavailable: %w", err)
		}

		targetConn, err = sshClient.Dial("tcp", targetAddr)
		if err != nil {
			log.Printf("Failed to dial target %s via SSH (attempt %d/%d): %v", targetAddr, retry+1, maxRetries, err)
			s.sshManager.markUnhealthy()
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			s.sendReply(clientConn, socks5HostUnreachable, nil)
			return fmt.Errorf("dial target: %w", err)
		}

		break
	}
	defer targetConn.Close()

	// 发送成功响应
	if err := s.sendReply(clientConn, socks5Success, targetConn.LocalAddr()); err != nil {
		return fmt.Errorf("send reply: %w", err)
	}

	// 双向转发数据
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()

	wg.Wait()
	return nil
}

// 解析 SSH 配置文件
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

		// 跳过注释和空行
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
			currentConfig = &SSHConfig{
				Host: value,
				Port: "22", // 默认端口
			}
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
				// 展开 ~ 为用户主目录
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
				// 支持逗号分隔的多个跳板
				jumps := strings.Split(value, ",")
				for i := range jumps {
					jumps[i] = strings.TrimSpace(jumps[i])
				}
				currentConfig.ProxyJump = jumps
			}
		}
	}

	// 保存最后一个配置
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

// 获取当前有效的 SSH 客户端（带自动重连）
func (m *SSHManager) getSSHClient() (*ssh.Client, error) {
	m.mu.RLock()
	client := m.client
	healthy := m.clientHealthy
	m.mu.RUnlock()

	// 如果客户端存在且健康，先尝试使用
	if client != nil && healthy {
		// 测试连接是否真的可用
		if m.testConnection(client) {
			return client, nil
		}
		// 连接测试失败，标记为不健康并关闭
		log.Println("SSH connection test failed, marking as unhealthy")
		m.markUnhealthy()
	}

	// 需要重新连接
	return m.reconnect()
}

// 测试 SSH 连接是否真的可用
func (m *SSHManager) testConnection(client *ssh.Client) bool {
	// 方法1：尝试发送 keepalive
	_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		return false
	}

	// 方法2（更可靠）：尝试打开一个会话
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	session.Close()

	return true
}

// 标记当前连接为不健康并关闭
func (m *SSHManager) markUnhealthy() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}

	// 关闭所有跳板机连接
	for _, jc := range m.jumpClients {
		if jc != nil {
			jc.Close()
		}
	}
	m.jumpClients = nil
	m.clientHealthy = false
}

func (m *SSHManager) reconnect() (*ssh.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 双重检查：如果已有健康的连接，直接返回
	if m.client != nil && m.clientHealthy {
		return m.client, nil
	}

	// 清理旧连接
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
	m.clientHealthy = false

	for {
		var client *ssh.Client
		var err error

		if m.sshConfigHost != "" {
			log.Printf("Connecting via SSH config host: %s", m.sshConfigHost)
			client, err = m.dialSSHWithConfig()
		} else {
			log.Printf("Connecting to SSH server: %s", m.sshHost)
			client, err = m.dialSSH()
		}

		if err == nil {
			m.client = client
			m.clientHealthy = true
			m.lastError = nil
			log.Println("SSH connection established")
			go m.keepAlive(client)
			return client, nil
		}

		m.lastError = err
		log.Printf("Failed to connect SSH: %v, retrying in %v...", err, m.reconnectSec)

		// 在重试期间释放锁，避免阻塞其他请求
		m.mu.Unlock()
		time.Sleep(m.reconnectSec)
		m.mu.Lock()

		// 重新获取锁后，检查是否已经有其他协程建立了连接
		if m.client != nil && m.clientHealthy {
			return m.client, nil
		}
	}
}

// 通过 SSH 配置文件建立连接（支持多级跳板，使用 SSH -W 模式）
func (m *SSHManager) dialSSHWithConfig() (*ssh.Client, error) {
	config, err := parseSSHConfig(m.sshConfigFile, m.sshConfigHost)
	if err != nil {
		return nil, err
	}

	// 读取所有跳板的配置
	allConfigs, err := m.loadAllSSHConfigs()
	if err != nil {
		return nil, err
	}

	// 准备目标服务器的认证方式
	targetAuth, err := m.getAuthMethods(config)
	if err != nil {
		return nil, err
	}

	targetAddr := config.HostName + ":" + config.Port
	targetUser := config.User
	if targetUser == "" {
		targetUser = m.sshUser
	}

	// 如果没有跳板，直接连接
	if len(config.ProxyJump) == 0 {
		log.Printf("Direct connection to %s@%s", targetUser, targetAddr)
		return m.dialSSHDirect(targetAddr, targetUser, targetAuth)
	}

	// 有跳板，使用 SSH -W 模式建立隧道
	log.Printf("Connecting through %d jump server(s) using SSH -W mode", len(config.ProxyJump))

	return m.dialSSHWithJumps(config, allConfigs, targetUser, targetAddr, targetAuth)
}

// 加载所有 SSH 配置
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

// 使用 SSH -W (direct-tcpip) 模式建立多级跳板连接
func (m *SSHManager) dialSSHWithJumps(targetConfig *SSHConfig, allConfigs map[string]*SSHConfig, targetUser, targetAddr string, targetAuth []ssh.AuthMethod) (*ssh.Client, error) {
	// 连接第一个跳板
	firstJumpName := targetConfig.ProxyJump[0]
	firstJumpConfig, ok := allConfigs[firstJumpName]
	if !ok {
		return nil, fmt.Errorf("jump host %s not found in config", firstJumpName)
	}

	firstJumpAuth, err := m.getAuthMethods(firstJumpConfig)
	if err != nil {
		return nil, fmt.Errorf("get auth for first jump %s: %w", firstJumpName, err)
	}

	firstJumpAddr := firstJumpConfig.HostName + ":" + firstJumpConfig.Port
	firstJumpUser := firstJumpConfig.User
	if firstJumpUser == "" {
		firstJumpUser = m.sshUser
	}

	log.Printf("Connecting to first jump: %s@%s", firstJumpUser, firstJumpAddr)
	currentClient, err := m.dialSSHDirect(firstJumpAddr, firstJumpUser, firstJumpAuth)
	if err != nil {
		return nil, fmt.Errorf("connect to first jump %s: %w", firstJumpName, err)
	}

	// 保存跳板机连接用于后续清理
	m.jumpClients = append(m.jumpClients, currentClient)

	// 如果有多个跳板，依次通过 SSH -W 模式连接
	for i := 1; i < len(targetConfig.ProxyJump); i++ {
		jumpName := targetConfig.ProxyJump[i]
		jumpConfig, ok := allConfigs[jumpName]
		if !ok {
			m.closeJumpClients()
			return nil, fmt.Errorf("jump host %s not found in config", jumpName)
		}

		jumpAuth, err := m.getAuthMethods(jumpConfig)
		if err != nil {
			m.closeJumpClients()
			return nil, fmt.Errorf("get auth for jump %s: %w", jumpName, err)
		}

		jumpAddr := jumpConfig.HostName + ":" + jumpConfig.Port
		jumpUser := jumpConfig.User
		if jumpUser == "" {
			jumpUser = m.sshUser
		}

		log.Printf("Connecting to jump %d via SSH -W: %s@%s", i+1, jumpUser, jumpAddr)

		// 使用 SSH -W 模式（direct-tcpip channel）建立隧道
		nextClient, err := m.dialSSHThroughDirectTCPIP(currentClient, jumpAddr, jumpUser, jumpAuth)
		if err != nil {
			m.closeJumpClients()
			return nil, fmt.Errorf("connect to jump %s via SSH -W: %w", jumpName, err)
		}

		m.jumpClients = append(m.jumpClients, nextClient)
		currentClient = nextClient
	}

	// 通过最后一个跳板使用 SSH -W 连接目标服务器
	log.Printf("Connecting to target via SSH -W: %s@%s", targetUser, targetAddr)
	finalClient, err := m.dialSSHThroughDirectTCPIP(currentClient, targetAddr, targetUser, targetAuth)
	if err != nil {
		m.closeJumpClients()
		return nil, fmt.Errorf("connect to target via SSH -W: %w", err)
	}

	return finalClient, nil
}

// 关闭所有跳板机连接
func (m *SSHManager) closeJumpClients() {
	for _, jc := range m.jumpClients {
		if jc != nil {
			jc.Close()
		}
	}
	m.jumpClients = nil
}

// 获取认证方式
func (m *SSHManager) getAuthMethods(config *SSHConfig) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod

	// 优先使用配置文件中的密码
	if config.Password != "" {
		auth = append(auth, ssh.Password(config.Password))
	} else if m.sshPassword != "" {
		// 其次使用命令行参数的密码
		auth = append(auth, ssh.Password(m.sshPassword))
	}
	// 使用配置文件中的私钥或命令行参数的私钥
	keyFile := config.IdentityFile
	if keyFile == "" && m.sshKeyFile != "" {
		keyFile = m.sshKeyFile
	}

	if keyFile != "" {
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read private key file %s: %w", keyFile, err)
		}

		var signer ssh.Signer
		var parseErr error

		if *sshKeyPassphrase != "" {
			signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(*sshKeyPassphrase))
			if parseErr != nil {
				return nil, fmt.Errorf("parse encrypted private key %s: %w", keyFile, parseErr)
			}
		} else {
			signer, parseErr = ssh.ParsePrivateKey(keyBytes)
			if parseErr != nil {
				// 可能需要密码
				return nil, fmt.Errorf("parse private key %s (may need passphrase): %w", keyFile, parseErr)
			}
		}

		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("no authentication method available")
	}

	return auth, nil
}

// 直接连接 SSH 服务器
func (m *SSHManager) dialSSHDirect(addr, user string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	return ssh.Dial("tcp", addr, config)
}

// 通过已有 SSH 客户端使用 direct-tcpip channel（SSH -W 模式）连接下一跳
func (m *SSHManager) dialSSHThroughDirectTCPIP(jumpClient *ssh.Client, targetAddr, targetUser string, targetAuth []ssh.AuthMethod) (*ssh.Client, error) {
	// 使用 direct-tcpip channel 类型，这是 SSH -W 的底层实现
	// 这相当于 ssh -W targetHost:targetPort jumpHost
	log.Printf("Opening direct-tcpip channel to %s", targetAddr)

	conn, err := jumpClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial through jump host via direct-tcpip: %w", err)
	}

	// 通过隧道连接建立 SSH 客户端
	config := &ssh.ClientConfig{
		User:            targetUser,
		Auth:            targetAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake through tunnel: %w", err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

func parseShellPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Printf("Failed to get user home directory: %v", err)
			return path
		}
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

// 原有的直接拨号方法（用于命令行参数方式）
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
		var parseErr error

		if *sshKeyPassphrase != "" {
			signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(*sshKeyPassphrase))
			if parseErr == nil {
				auth = append(auth, ssh.PublicKeys(signer))
			} else {
				return nil, fmt.Errorf("failed to parse encrypted private key with given passphrase: %w", parseErr)
			}
		} else {
			signer, parseErr = ssh.ParsePrivateKey(keyBytes)
			if parseErr == nil {
				auth = append(auth, ssh.PublicKeys(signer))
			} else {
				return nil, fmt.Errorf("failed to parse private key (it may be encrypted; try --ssh-key-passphrase): %w", parseErr)
			}
		}
	}

	if !strings.Contains(m.sshHost, ":") {
		m.sshHost = m.sshHost + ":22"
	}

	config := &ssh.ClientConfig{
		User:            m.sshUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	return ssh.Dial("tcp", m.sshHost, config)
}

// 保活协程
func (m *SSHManager) keepAlive(client *ssh.Client) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Printf("SSH keepalive failed: %v", err)
				m.mu.Lock()
				if m.client == client {
					m.clientHealthy = false
					m.client.Close()
					m.client = nil
					// 同时关闭所有跳板机连接
					for _, jc := range m.jumpClients {
						if jc != nil {
							jc.Close()
						}
					}
					m.jumpClients = nil
				}
				m.mu.Unlock()
				return
			}
		}
	}
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

	creds := string(payload)
	parts := strings.SplitN(creds, ":", 2)
	if len(parts) != 2 {
		return false
	}

	username := parts[0]
	password := parts[1]

	return username == *httpProxyUser && password == *httpProxyPass
}

// ServeHTTP 实现 HTTP 代理逻辑
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	log.Printf("[HTTP] Client %s -> Target %s %s %s", clientIP, r.URL.Host, r.Method, r.URL.Path)

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

	var sshClient *ssh.Client
	var targetConn net.Conn
	maxRetries := 3

	for retry := 0; retry < maxRetries; retry++ {
		sshClient, err = p.sshManager.getSSHClient()
		if err != nil {
			log.Printf("Failed to get SSH client for CONNECT (attempt %d/%d): %v", retry+1, maxRetries, err)
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			clientConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
			return
		}

		targetConn, err = sshClient.Dial("tcp", dest)
		if err != nil {
			log.Printf("Failed to dial target %s via SSH (attempt %d/%d): %v", dest, retry+1, maxRetries, err)
			p.sshManager.markUnhealthy()
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		break
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()

	wg.Wait()
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.String(), "http") {
		http.Error(w, "URL must be absolute", http.StatusBadRequest)
		return
	}

	maxRetries := 3
	var sshClient *ssh.Client
	var targetConn net.Conn
	var err error

	for retry := 0; retry < maxRetries; retry++ {
		sshClient, err = p.sshManager.getSSHClient()
		if err != nil {
			log.Printf("Failed to get SSH client (attempt %d/%d): %v", retry+1, maxRetries, err)
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			http.Error(w, "SSH unavailable", http.StatusServiceUnavailable)
			return
		}

		targetConn, err = sshClient.Dial("tcp", r.URL.Host)
		if err != nil {
			log.Printf("Failed to dial %s (attempt %d/%d): %v", r.URL.Host, retry+1, maxRetries, err)
			p.sshManager.markUnhealthy()
			if retry < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(retry+1))
				continue
			}
			http.Error(w, "Gateway error", http.StatusBadGateway)
			return
		}

		break
	}
	defer targetConn.Close()

	err = r.Write(targetConn)
	if err != nil {
		log.Printf("Failed to write request: %v", err)
		http.Error(w, "Write error", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
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
