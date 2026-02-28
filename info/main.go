package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modood/table"
)

const (
	defaultSealosEnvPath = "/root/.sealos/cloud/sealos.env"
)

const (
	colorReset     = "\033[0m"
	colorRed       = "\033[31m"
	colorCyan      = "\033[36m"
	colorYellow    = "\033[33m"
	colorPurple    = "\033[35m"
	colorGreenBold = "\033[1;32m\033[1m"
)

type logger struct{}

// ServiceInfo 服务信息表格结构
type ServiceInfo struct {
	Name        string
	User        string
	Password    string
	Version     string
	PublishAddr string
}

func (l logger) timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func (l logger) errorf(format string, args ...any) {
	flag := l.timestamp()
	fmt.Printf("%s ERROR [%s] >> %s %s\n", colorRed, flag, fmt.Sprintf(format, args...), colorReset)
	os.Exit(1)
}

func (l logger) infof(format string, args ...any) {
	flag := l.timestamp()
	fmt.Printf("%s INFO [%s] >> %s %s\n", colorCyan, flag, fmt.Sprintf(format, args...), colorReset)
}

func (l logger) warnf(format string, args ...any) {
	flag := l.timestamp()
	fmt.Printf("%s WARN [%s] >> %s %s\n", colorYellow, flag, fmt.Sprintf(format, args...), colorReset)
}

func (l logger) debugf(format string, args ...any) {
	flag := l.timestamp()
	fmt.Printf("%s DEBUG [%s] >> %s %s\n", colorPurple, flag, fmt.Sprintf(format, args...), colorReset)
}

func (l logger) printf(format string, args ...any) {
	flag := l.timestamp()
	fmt.Printf("%s INFO [%s] >> %s %s\n", colorGreenBold, flag, fmt.Sprintf(format, args...), colorReset)
}

func main() {
	log := logger{}

	sealosEnvPath := flag.String("sealos-env", defaultSealosEnvPath, "sealos.env 文件路径")
	onlyNsAdmin := flag.Bool("only-ns-admin", false, "仅生成 ns-admin 登录链接")
	skipNsAdmin := flag.Bool("skip-ns-admin", false, "跳过 ns-admin 登录链接生成")
	nsAdminUserID := flag.String("ns-admin-user-id", "admin", "ns-admin 登录用户 ID")
	nsAdminUserUID := flag.String("ns-admin-user-uid", "", "ns-admin 登录用户 UID（可为空自动查）")
	nsAdminNamespace := flag.String("ns-admin-namespace", "admin-system", "ns-admin configmap 所在命名空间")
	nsAdminConfigMap := flag.String("ns-admin-configmap", "admin-sealos-admin", "ns-admin configmap 名称")
	flag.Parse()

	if _, err := exec.LookPath("kubectl"); err != nil {
		log.errorf("kubectl 未安装或不在 PATH 中")
	}

	log.infof("Sealos Cloud")

	sealosEnv, err := loadEnvFile(*sealosEnvPath)
	if err != nil {
		log.errorf("Sealos cloud not found %s. Please install sealos cloud first.", *sealosEnvPath)
	}
	log.infof("Loading configuration from %s", *sealosEnvPath)

	sealosCloudDomain := firstNonEmpty(sealosEnv["SEALOS_V2_CLOUD_DOMAIN"], sealosEnv["SEALOS_CLOUD_DOMAIN"])
	sealosCloudPort := firstNonEmpty(sealosEnv["SEALOS_V2_CLOUD_PORT"], sealosEnv["SEALOS_CLOUD_PORT"])

	k8sVersion, err := getKubernetesVersion()
	if err != nil {
		log.warnf("获取 Kubernetes 版本失败: %v", err)
	}

	sealosCloudVersion, err := getSealosCloudVersion()
	if err != nil {
		log.warnf("获取 Sealos Cloud 版本失败: %v", err)
	}

	if !*onlyNsAdmin {
		// 收集所有服务信息
		var services []ServiceInfo

		services = append(services, minioInfo(sealosCloudDomain)...)
		services = append(services, grafanaInfo(sealosCloudDomain)...)
		services = append(services, vmInfo(sealosCloudDomain)...)
		services = append(services, vlogsInfo(sealosCloudDomain)...)
		services = append(services, hamiInfo()...) // 添加 HAMI 信息
		services = append(services, finishInfo(sealosCloudDomain, sealosCloudPort, k8sVersion, sealosCloudVersion)...)
		services = append(services, aiproxyInfo(sealosCloudDomain)...)   // 添加 AIProxy 信息
		services = append(services, cockroachInfo(sealosCloudDomain)...) // 添加 CockroachDB 信息

		// 输出表格
		if len(services) > 0 {
			log.printf("")
			table.Output(services)
		} else {
			log.warnf("未找到任何服务信息")
		}

		// 单独输出证书信息
		tlsTips(log, sealosCloudDomain)
	}

	if !*skipNsAdmin {
		userID := strings.TrimSpace(*nsAdminUserID)
		if userID == "" {
			userID = "admin"
		}
		link, err := generateNsAdminLink(*nsAdminNamespace, *nsAdminConfigMap, userID, *nsAdminUserUID)
		if err != nil {
			if *onlyNsAdmin {
				log.errorf("生成 ns-admin 登录链接失败: %v", err)
			} else {
				log.warnf("生成 ns-admin 登录链接失败: %v", err)
			}
		} else {
			log.infof("ns-admin 登录链接:")
			log.printf("%s", link)
		}
	}
}

func loadEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	envs := map[string]string{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		envs[key] = val
	}
	return envs, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func runShell(command string) (string, error) {
	return runCommand("sh", "-c", command)
}

func getKubernetesVersion() (string, error) {
	output, err := runCommand("kubectl", "version", "-o", "json")
	if err != nil {
		return "", err
	}
	var payload struct {
		ServerVersion struct {
			GitVersion string `json:"gitVersion"`
		} `json:"serverVersion"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return "", err
	}
	return strings.TrimPrefix(payload.ServerVersion.GitVersion, "v"), nil
}

func getSealosCloudVersion() (string, error) {
	deploys := []string{
		"desktop-frontend",
		"sealos-desktop",
	}
	for _, deploy := range deploys {
		image, err := runCommand("kubectl", "get", "deployment", deploy, "-n", "sealos",
			"-o", "jsonpath={.spec.template.spec.containers[0].image}")
		if err == nil && image != "" {
			lastColon := strings.LastIndex(image, ":")
			if lastColon != -1 && lastColon != len(image)-1 {
				return image[lastColon+1:], nil
			}
		}
	}
	return "", fmt.Errorf("未找到 Sealos Cloud 版本信息")
}

func finishInfo(domain, port, k8sVersion, sealosCloudVersion string) []ServiceInfo {
	var services []ServiceInfo

	adminPassword, err := runCommand("kubectl", "get", "cm", "sealos-cloud-admin", "-n", "sealos-system",
		"-o", "jsonpath={.data.PASSWORD}", "--ignore-not-found")
	if err != nil {
		adminPassword = ""
	}
	if strings.TrimSpace(adminPassword) == "" {
		adminPassword, err = runCommand("kubectl", "get", "job", "init-job", "-n", "account-system",
			"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ADMIN_PASSWORD\")].value}")
		if err != nil {
			adminPassword = "<获取失败>"
		}
	}

	// 添加主服务信息
	services = append(services, ServiceInfo{
		Name:        "Sealos Cloud",
		User:        "admin",
		Password:    adminPassword,
		Version:     sealosCloudVersion,
		PublishAddr: fmt.Sprintf("https://%s:%s", domain, port),
	})

	// 添加Kubernetes版本信息
	services = append(services, ServiceInfo{
		Name:        "Kubernetes",
		User:        "-",
		Password:    "-",
		Version:     k8sVersion,
		PublishAddr: "-",
	})

	return services
}

func minioInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	consoleUser, err := runCommand("kubectl", "get", "cm", "objectstorage-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.MINIO_CONSOLE_USER}")
	if err != nil {
		return services
	}
	consolePassword, _ := runCommand("kubectl", "get", "cm", "objectstorage-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.MINIO_CONSOLE_PASSWORD}")
	kbUser, _ := runCommand("kubectl", "get", "cm", "objectstorage-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.MINIO_KB_USER}")
	kbPassword, _ := runCommand("kubectl", "get", "cm", "objectstorage-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.MINIO_KB_PASSWORD}")
	testUserPassword, _ := runCommand("kubectl", "get", "cm", "objectstorage-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.MINIO_TESTUSER_PASSWORD}")

	minioURL := fmt.Sprintf("https://osconsole.%s", domain)

	// MinIO Console
	services = append(services, ServiceInfo{
		Name:        "MinIO Console",
		User:        consoleUser,
		Password:    consolePassword,
		Version:     "-",
		PublishAddr: minioURL,
	})

	// MinIO KB
	services = append(services, ServiceInfo{
		Name:        "MinIO KB",
		User:        kbUser,
		Password:    kbPassword,
		Version:     "-",
		PublishAddr: minioURL,
	})

	// MinIO Test User
	services = append(services, ServiceInfo{
		Name:        "MinIO Test",
		User:        "testuser",
		Password:    testUserPassword,
		Version:     "-",
		PublishAddr: minioURL,
	})

	return services
}

func grafanaInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	adminPassword, err := runCommand("kubectl", "get", "cm", "grafana-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.GF_PASSWORD}")
	if err != nil {
		return services
	}
	adminUser, _ := runCommand("kubectl", "get", "cm", "grafana-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.GF_USER}")

	services = append(services, ServiceInfo{
		Name:        "Grafana",
		User:        adminUser,
		Password:    adminPassword,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://gggggrafana.%s", domain),
	})

	return services
}

func vmInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	secretName := "vmuser-vm-stack-victoria-metrics-k8s-stack"
	ns := "vm"

	nameB64, err := runCommand("kubectl", "get", "secrets", secretName, "-n", ns,
		"-o", "jsonpath={.data.name}")
	if err != nil {
		return services
	}

	passwordB64, _ := runCommand("kubectl", "get", "secrets", secretName, "-n", ns,
		"-o", "jsonpath={.data.password}")

	usernameB64, _ := runCommand("kubectl", "get", "secrets", secretName, "-n", ns,
		"-o", "jsonpath={.data.username}")

	name := decodeBase64(nameB64)
	username := decodeBase64(usernameB64)
	password := decodeBase64(passwordB64)

	// 如果三个值都为空，视为整体失败
	if name == "" && username == "" && password == "" {
		return services
	}

	// VictoriaMetrics vmui
	services = append(services, ServiceInfo{
		Name:        "VictoriaMetrics VMUI",
		User:        username,
		Password:    password,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://vmmmmauth.%s/vmui", domain),
	})

	// VictoriaMetrics Agent
	services = append(services, ServiceInfo{
		Name:        "VictoriaMetrics Agent",
		User:        username,
		Password:    password,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://vmmmmagent.%s", domain),
	})

	return services
}

func vlogsInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	sysUser, err := runCommand("kubectl", "get", "configmap", "vlogs-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.SELECT_USER}")
	if err != nil {
		return services
	}
	sysPassword, _ := runCommand("kubectl", "get", "configmap", "vlogs-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.SELECT_PASSWORD}")

	userUser, _ := runCommand("kubectl", "get", "configmap", "vlogs-config-user", "-n", "sealos-system",
		"-o", "jsonpath={.data.SELECT_USER}")
	userPassword, _ := runCommand("kubectl", "get", "configmap", "vlogs-config-user", "-n", "sealos-system",
		"-o", "jsonpath={.data.SELECT_PASSWORD}")

	// System Logs
	services = append(services, ServiceInfo{
		Name:        "System Logs",
		User:        sysUser,
		Password:    sysPassword,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://vvvvvvlogs.%s", domain),
	})

	// User Logs
	services = append(services, ServiceInfo{
		Name:        "User Logs",
		User:        userUser,
		Password:    userPassword,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://vvvvvvuserlogs.%s", domain),
	})

	return services
}

func hamiInfo() []ServiceInfo {
	var services []ServiceInfo

	// 读取 HAMI webui 配置
	webuiAddress, err := runCommand("kubectl", "get", "cm", "hami-webui-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.HAMI_WEBUI_ADDRESS}")
	if err != nil {
		// HAMI 配置不存在，直接返回空数组
		return services
	}

	webuiUser, _ := runCommand("kubectl", "get", "cm", "hami-webui-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.HAMI_WEBUI_USER}")
	webuiPassword, _ := runCommand("kubectl", "get", "cm", "hami-webui-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.HAMI_WEBUI_PASSWORD}")

	// 添加 HAMI WebUI 信息到表格
	services = append(services, ServiceInfo{
		Name:        "HAMI WebUI",
		User:        webuiUser,
		Password:    webuiPassword,
		Version:     "-",
		PublishAddr: webuiAddress,
	})

	return services
}

func aiproxyInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	// 读取 AIProxy 配置
	adminKey, err := runCommand("kubectl", "get", "configmap", "aiproxy-env", "-n", "aiproxy-system",
		"-o", "jsonpath={.data.ADMIN_KEY}")
	if err != nil {
		// AIProxy 配置不存在，直接返回空数组
		return services
	}
	aiproxyURL := fmt.Sprintf("https://aiproxy.%s", domain)
	// 添加 AIProxy 信息到表格
	services = append(services, ServiceInfo{
		Name:        "AIProxy",
		User:        "admin",
		Password:    adminKey,
		Version:     "-",
		PublishAddr: aiproxyURL,
	})

	return services
}

func cockroachInfo(domain string) []ServiceInfo {
	var services []ServiceInfo

	// 读取 CockroachDB URI
	uri, err := runCommand("kubectl", "get", "configmap", "sealos-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.databaseGlobalCockroachdbURI}")
	if err != nil {
		// CockroachDB 配置不存在，直接返回空数组
		return services
	}

	// 解析 URI: postgresql://username:password@host:port/database
	// 示例: postgresql://root:password@cockroachdb.sealos.svc:26257/defaultdb
	parsedURI := uri
	if strings.HasPrefix(parsedURI, "postgresql://") {
		parsedURI = strings.TrimPrefix(parsedURI, "postgresql://")
	}

	// 提取用户名和密码
	// 格式: username:password@host:port/database
	var username, password string
	atIndex := strings.Index(parsedURI, "@")
	if atIndex != -1 {
		// 获取 @ 之前的部分（username:password）
		userPassPart := parsedURI[:atIndex]
		colonIndex := strings.Index(userPassPart, ":")
		if colonIndex != -1 {
			username = userPassPart[:colonIndex]
			password = userPassPart[colonIndex+1:]
		}
	}

	// 添加 CockroachDB 信息到表格
	services = append(services, ServiceInfo{
		Name:        "CockroachDB",
		User:        username,
		Password:    password,
		Version:     "-",
		PublishAddr: fmt.Sprintf("https://cockroachdb.%s", domain),
	})

	return services
}

func tlsTips(log logger, domain string) {
	acmeDNS, err := runCommand("kubectl", "get", "configmap", "cert-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.ACMEDNS_FULL_DOMAIN}")
	if err != nil {
		log.warnf("读取 TLS 配置失败: %v", err)
		return
	}
	certMode, _ := runCommand("kubectl", "get", "configmap", "cert-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.CERT_MODE}")
	dnsmasqEnabled, _ := runCommand("kubectl", "get", "configmap", "cert-config", "-n", "sealos-system",
		"-o", "jsonpath={.data.DNSMASQ_ENABLED}")

	log.printf("TLS certificate information (important - please review):")
	switch certMode {
	case "acmedns":
		log.printf("A CNAME record should point %s to the ACME DNS name provided during installation.", domain)
		log.printf("Create a CNAME record for '_acme-challenge.%s' pointing to the %s.", domain, acmeDNS)
	case "self-signed":
		log.printf("No TLS certificate provided — a self-signed certificate will be used by Sealos Cloud.")
		log.printf("Browsers and clients will show a warning unless the self-signed certificate is trusted.")
		log.printf("To trust the certificate, follow the guide: https://sealos.run/docs/self-hosting/install#信任自签名证书")
	case "https":
		log.printf("A custom TLS certificate and private key were provided.")
		log.printf("Ensure the DNS name %s resolves to this server's IP so the certificate is valid.", domain)
		log.printf("If you encounter certificate errors in clients, verify the certificate chain and that the hostname matches.")
	case "offline":
		log.printf("Offline mode selected — TLS certificates are not managed by Sealos Cloud.")
		log.printf("Ensure that the existing certificates on the cluster are valid and trusted by clients.")

		// 检查 DNSMasq 是否启用(不区分大小写)
		if strings.ToLower(strings.TrimSpace(dnsmasqEnabled)) != "true" {
			manualDomain := domain
			log.printf("DNSMasq is disabled. Please configure DNS records for %s, *.%s, and update.code.visualstudio.com.", manualDomain, manualDomain)
		}

		log.printf("All offline files have been copied to the NGINX location.")

		// 获取本地IP
		localIP, err := getLocalIP()
		if err != nil {
			log.warnf("获取本地IP失败: %v", err)
			localIP = "<your-server-ip>"
		}
		log.printf("Please visit: http://%s:32000 to verify offline resources are accessible.", localIP)
	default:
		log.errorf("Unknown CERT_MODE: %s", certMode)
	}
}

// getLocalIP 获取本机IP地址
func getLocalIP() (string, error) {
	// 尝试使用 hostname -I 命令获取IP
	output, err := runCommand("hostname", "-I")
	if err != nil {
		// 如果 hostname -I 失败，尝试使用 ip route get 1
		output, err = runShell("ip route get 1 | awk '{print $7}' | head -1")
		if err != nil {
			// 如果都失败，尝试使用 ifconfig
			output, err = runShell("ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -1")
			if err != nil {
				return "", fmt.Errorf("无法获取本地IP地址")
			}
		}
	}

	// hostname -I 可能返回多个IP，取第一个
	parts := strings.Fields(output)
	if len(parts) == 0 {
		return "", fmt.Errorf("未找到有效的IP地址")
	}

	return parts[0], nil
}

func decodeBase64(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return value
	}
	return string(decoded)
}

func generateNsAdminLink(namespace, configMap, userID, userUID string) (string, error) {
	envContent, err := runCommand("kubectl", "get", "cm", configMap, "-n", namespace,
		"-o", "jsonpath={.data['.env']}")
	envMap := map[string]string{}
	if err == nil && envContent != "" {
		envMap = parseEnvContent(envContent)
	}
	tokenPrefix := envMap["TOKEN_URL_PREFIX"]
	secret := envMap["GENERATE_TOKEN"]
	globalDBURI := firstNonEmpty(envMap["GLOBAL_COCKROACHDB_URI"], envMap["globalCockroachdbURI"])
	if tokenPrefix == "" || secret == "" {
		confignames := []string{
			"desktop-frontend-config",
			"sealos-desktop-config",
		}
		for _, cfgName := range confignames {
			cfgContent, cfgErr := runCommand("kubectl", "get", "cm", cfgName, "-n", "sealos",
				"-o", "jsonpath={.data.config\\.yaml}", "--ignore-not-found")
			if cfgErr == nil && cfgContent != "" {
				domain, jwtGlobal, dbURI := parseDesktopFrontendConfig(cfgContent)
				if tokenPrefix == "" && domain != "" {
					tokenPrefix = fmt.Sprintf("https://%s/switchRegion?token=", domain)
				}
				if secret == "" && jwtGlobal != "" {
					secret = jwtGlobal
				}
				if globalDBURI == "" && dbURI != "" {
					globalDBURI = dbURI
				}
				if tokenPrefix != "" && secret != "" {
					break
				}
			}
		}
	}
	if tokenPrefix == "" || secret == "" {
		return "", fmt.Errorf("TOKEN_URL_PREFIX 或 GENERATE_TOKEN 为空")
	}
	resolvedUID := strings.TrimSpace(userUID)
	if resolvedUID == "" {
		if globalDBURI == "" {
			return "", fmt.Errorf("未提供用户 UID，且无法获取 GLOBAL_COCKROACHDB_URI")
		}
		var err error
		resolvedUID, err = lookupUserUID(globalDBURI, userID)
		if err != nil {
			return "", err
		}
	}
	token, err := buildJWT(userID, resolvedUID, secret)
	if err != nil {
		return "", err
	}
	return tokenPrefix + token, nil
}

func parseEnvContent(content string) map[string]string {
	envs := map[string]string{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		envs[key] = val
	}
	return envs
}

type yamlKey struct {
	indent int
	key    string
}

func parseDesktopFrontendConfig(content string) (string, string, string) {
	var domain string
	var jwtGlobal string
	var dbURI string
	lines := strings.Split(content, "\n")
	stack := make([]yamlKey, 0, 8)
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingSpaces(rawLine)
		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := ""
		if len(parts) > 1 {
			value = strings.TrimSpace(parts[1])
		}

		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		if value == "" {
			stack = append(stack, yamlKey{indent: indent, key: key})
			continue
		}

		value = strings.Trim(value, `"'`)
		path := buildPath(stack, key)
		if path == "cloud.domain" && domain == "" {
			domain = value
		}
		if path == "desktop.auth.jwt.global" && jwtGlobal == "" {
			jwtGlobal = value
		}
		if path == "database.globalCockroachdbURI" && dbURI == "" {
			dbURI = value
		}
	}
	return domain, jwtGlobal, dbURI
}

func leadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		if ch != ' ' && ch != '\t' {
			break
		}
		count++
	}
	return count
}

func buildPath(stack []yamlKey, leaf string) string {
	if len(stack) == 0 {
		return leaf
	}
	parts := make([]string, 0, len(stack)+1)
	for _, item := range stack {
		parts = append(parts, item.key)
	}
	parts = append(parts, leaf)
	return strings.Join(parts, ".")
}

func lookupUserUID(dbURI, userID string) (string, error) {
	query := fmt.Sprintf("SELECT id, uid FROM \"User\" WHERE id='%s' LIMIT 1;", escapeSQLLiteral(userID))
	if _, err := exec.LookPath("psql"); err == nil {
		output, err := runCommand("psql", dbURI, "-t", "-A", "-F", ",", "-c", query)
		if err != nil {
			return "", fmt.Errorf("psql 查询失败: %v", err)
		}
		return parseUserUIDLine(output, userID)
	}
	if _, err := exec.LookPath("cockroach"); err == nil {
		output, err := runCommand("cockroach", "sql", "--url", dbURI, "--format=csv", "-e", query)
		if err != nil {
			return "", fmt.Errorf("cockroach 查询失败: %v", err)
		}
		return parseUserUIDCSV(output, userID)
	}
	podName, err := findCockroachPod()
	if err != nil {
		return "", err
	}
	localURL, urlErr := rewriteCockroachURLForLocalhost(dbURI)
	if urlErr != nil {
		return "", urlErr
	}
	output, err := runCommand(
		"kubectl",
		"exec",
		"-n",
		"sealos",
		podName,
		"-c",
		"db",
		"--",
		"cockroach",
		"sql",
		"--certs-dir=/cockroach/cockroach-certs",
		"--url",
		localURL,
		"--format=csv",
		"-e",
		query,
	)
	if err != nil {
		return "", fmt.Errorf("cockroach pod 查询失败: %v", err)
	}
	return parseUserUIDCSV(output, userID)
}

func parseUserUIDLine(output, userID string) (string, error) {
	lines := strings.Split(output, "\n")
	line := ""
	for _, item := range lines {
		item = strings.TrimSpace(item)
		if item != "" {
			line = item
			break
		}
	}
	if line == "" {
		return "", fmt.Errorf("数据库未找到用户 %s", userID)
	}
	parts := strings.SplitN(line, ",", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("数据库输出格式异常")
	}
	uid := strings.TrimSpace(parts[1])
	if uid == "" {
		return "", fmt.Errorf("数据库未找到用户 %s 的 UID", userID)
	}
	return uid, nil
}

func parseUserUIDCSV(output, userID string) (string, error) {
	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		return "", fmt.Errorf("解析数据库输出失败: %v", err)
	}
	for _, row := range records {
		if len(row) < 2 {
			continue
		}
		if row[0] == userID {
			return row[1], nil
		}
	}
	return "", fmt.Errorf("数据库未找到用户 %s", userID)
}

func findCockroachPod() (string, error) {
	labels := []string{
		"app.kubernetes.io/name=cockroachdb",
		"app=cockroachdb",
		"app.kubernetes.io/component=cockroachdb",
	}
	for _, label := range labels {
		podName, err := runCommand("kubectl", "get", "pods", "-n", "sealos", "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
		if err == nil && strings.TrimSpace(podName) != "" {
			return strings.TrimSpace(podName), nil
		}
	}
	return "", fmt.Errorf("未找到 cockroachdb pod，且本地缺少 psql/cockroach 客户端")
}

func escapeSQLLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func rewriteCockroachURLForLocalhost(dbURI string) (string, error) {
	parsed, err := url.Parse(dbURI)
	if err != nil {
		return "", fmt.Errorf("解析数据库地址失败: %v", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("数据库地址格式不正确")
	}
	parsed.Host = "localhost:26257"
	query := parsed.Query()
	if query.Get("sslmode") == "" {
		query.Set("sslmode", "verify-full")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func buildJWT(userID, userUID, secret string) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := map[string]any{
		"userId":  userID,
		"userUid": userUID,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(3 * time.Hour).Unix(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := encodedHeader + "." + encodedPayload

	mac := hmacSHA256([]byte(secret), []byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac)
	return unsigned + "." + signature, nil
}

func hmacSHA256(secret, message []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}
