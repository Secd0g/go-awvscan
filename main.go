package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"gopkg.in/ini.v1"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
)

var (
	scanLabel         string
	headers           = make(http.Header)
	awvsURL           string
	apiKey            string
	istoscan          = 1
	profileID         string
	domainFile        string
	scanSpeed         string
	cookie            string
	customHeaders     string
	excludedPaths     string
	limitCrawlerScope string
	proxyEnabled      string
	proxyServer       string
	proxyPort         int
	description       string
	webhookURL        string
	// 创建一个自定义的 Transport，跳过证书验证
	//proxyURL, _ = url.Parse("http://127.0.0.1:8080")
	ssl = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL),
	}
	modID = map[string]string{
		"1":  "11111111-1111-1111-1111-111111111111", // 完全扫描
		"2":  "11111111-1111-1111-1111-111111111112", // 高风险漏洞
		"3":  "11111111-1111-1111-1111-111111111116", // XSS漏洞
		"4":  "11111111-1111-1111-1111-111111111113", // SQL注入漏洞
		"5":  "11111111-1111-1111-1111-111111111115", // 弱口令检测
		"6":  "11111111-1111-1111-1111-111111111117", // Crawl Only
		"7":  "11111111-1111-1111-1111-111111111120", // 恶意软件扫描
		"8":  "11111111-1111-1111-1111-111111111120", // 仅添加（这行不会生效）
		"9":  "apache-log4j",
		"10": "custom-Bounty",
		"11": "custom-cve",
		"12": "custom",
	}
)

type Target struct {
	TargetId string `json:"target_id"`
	Address  string `json:"address"`
}

type Pagination struct {
	Count      int    `json:"count"`
	CursorHash string `json:"cursor_hash"`
}
type ResponseData struct {
	Targets    []Target   `json:"targets"`
	Pagination Pagination `json:"pagination"`
}

func init() {
	// 指定 INI 文件路径
	cfg, err := ini.Load("config.ini")
	if err != nil {
		fmt.Printf("无法加载配置文件: %v\n", err)
		return
	}
	// 读取配置信息
	awvsURL = cfg.Section("awvs_url_key").Key("awvsURL").String()
	apiKey = cfg.Section("awvs_url_key").Key("apiKey").String()
	domainFile = cfg.Section("awvs_url_key").Key("domain_file").String()
	scanSpeed = cfg.Section("scan_seting").Key("scan_speed").String()
	cookie = cfg.Section("scan_seting").Key("cookie").String()
	// 创建一个 http.Header 对象并添加自定义的请求头
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Auth", apiKey)
	customHeaders = cfg.Section("scan_seting").Key("custom_headers").String()

	excludedPaths = cfg.Section("scan_seting").Key("excluded_paths").String()
	limitCrawlerScope = cfg.Section("scan_seting").Key("limit_crawler_scope").String()
	proxyEnabled = cfg.Section("scan_seting").Key("proxy_enabled").String()
	proxyServer = cfg.Section("scan_seting").Key("proxy_server").String()
	proxyPort, _ = cfg.Section("scan_seting").Key("proxy_port").Int()
	webhookURL = cfg.Section("scan_seting").Key("webhook_url").String()

	if !checkAuthentication() {
		os.Exit(1)
	} else {
		fmt.Println("配置正确~")
	}
}

func main() {

	fmt.Println(`
********************************************************************
Acunetix AWVS 批量添加，批量扫描，支持批量联动被动扫描器等功能
作者：F0rmat
********************************************************************
1 【批量添加url到AWVS扫描器扫描】
2 【删除扫描器内所有目标与扫描任务】
3 【删除所有扫描任务(不删除目标)】
4 【对扫描器中已有目标，进行扫描】
	`)

	var selection int
	fmt.Print("请输入数字: ")
	_, err := fmt.Scan(&selection)
	if err != nil {
		fmt.Println("输入无效:", err)
		return
	}
	switch selection {
	case 1:
		//调用模版选择界面
		profile_select()
	case 2:
		// 调用删除目标函数
		del_targets()
	case 3:
		// 调用删除任务函数
		del_tasks()
	case 4:
		istoscan = 2
		profile_select()
	default:
		fmt.Println("无效的选择")
	}

}

func configuration(targetID, target string) {
	var scancookie []map[string]string
	if cookie != "" {
		scancookie = []map[string]string{{"url": target, "cookie": cookie}}
	} else {
		scancookie = make([]map[string]string, 0)
	}
	var cushead []string
	json.Unmarshal([]byte(customHeaders), &cushead)
	var expath []interface{}
	json.Unmarshal([]byte(excludedPaths), &expath)
	configurationURL := fmt.Sprintf("%s/api/v1/targets/%s/configuration", awvsURL, targetID)
	data := map[string]interface{}{
		"scan_speed":                  scanSpeed,
		"login":                       map[string]string{"kind": "none"},
		"ssh_credentials":             map[string]string{"kind": "none"},
		"default_scanning_profile_id": profileID,
		"sensor":                      false,
		"user_agent":                  "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
		"case_sensitive":              "auto",
		"limit_crawler_scope":         limitCrawlerScope,
		"excluded_paths":              expath,
		"authentication":              map[string]bool{"enabled": false},
		"proxy": map[string]interface{}{
			"enabled":  proxyEnabled,
			"protocol": "http",
			"address":  proxyServer,
			"port":     proxyPort,
		},
		"technologies":                []interface{}{},
		"custom_headers":              cushead,
		"custom_cookies":              scancookie,
		"debug":                       false,
		"client_certificate_password": "",
		"issue_tracker_id":            "",
		"excluded_hours_id":           "",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("JSON 编码错误：%v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPatch, configurationURL, bytes.NewReader(jsonData))
	if err != nil {
		fmt.Printf("创建 HTTP 请求错误：%v\n", err)
		return
	}
	req.Header = headers

	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("HTTP 请求错误：%v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		fmt.Printf("配置失败，HTTP 状态码：%d\n", resp.StatusCode)
	}

}

func start_scan() {
	// 打开文件
	urlfile := "url.txt"
	file, err := os.Open(urlfile)
	if err != nil {
		fmt.Printf("无法打开文件：%s\n", err)
		return
	}
	defer file.Close()

	// 创建一个 Scanner 以逐行读取文件内容
	scanner := bufio.NewScanner(file)

	// 使用 WaitGroup 来等待所有协程完成
	var wg sync.WaitGroup

	// 启动多个协程处理文件中的每一行
	for scanner.Scan() {
		url := scanner.Text()
		// 每启动一个协程，增加 WaitGroup 的计数器
		wg.Add(1)
		go add_target(url, &wg)
	}
	// 等待所有协程完成
	wg.Wait()
	fmt.Println("处理完成")
	// 检查是否发生了扫描错误
	if err := scanner.Err(); err != nil {
		fmt.Printf("扫描文件出错：%s\n", err)
	}
}

func profile_select() {

	fmt.Println(`
选择要扫描的类型：
1 【开始 完全扫描】
2 【开始 扫描高风险漏洞】
3 【开始 扫描XSS漏洞】
4 【开始 扫描SQL注入漏洞】
5 【开始 弱口令检测】
6 【开始 Crawl Only,，建议config.ini配置好上级代理地址，联动被动扫描器】
7 【开始 扫描意软件扫描】
8 【仅添加 目标到扫描器，不做任何扫描】
9 【仅扫描apache-log4j】(请需先确保当前版本已支持log4j扫描,awvs 14.6.211220100及以上)
10 【开始扫描Bug Bounty高频漏洞】
11 【扫描已知漏洞】（常见CVE，POC等）
12 【自定义模板】
	`)
	var selection2 int
	fmt.Print("请输入数字: ")
	_, err := fmt.Scan(&selection2)
	if err != nil {
		fmt.Println("输入无效:", err)
		return
	}
	if selection2 == 8 {
		istoscan = 0
	} else if selection2 == 9 {
		profileID = customLog4j()
	} else if selection2 == 10 {
		profileID = custom_bug_bounty()
	} else if selection2 == 11 {
		profileID = custom_cves()
	} else if selection2 == 12 {
		var selection3 string
		fmt.Print("请输入已定义好模板profile_id: ")
		_, err = fmt.Scan(&selection3)
		if err != nil {
			fmt.Println("输入无效:", err)
			return
		}
		profileID = selection3
	} else {
		profileID = modID[strconv.Itoa(selection2)]

	}
	if istoscan == 2 {
		// 使用 WaitGroup 来等待所有协程完成
		var wg sync.WaitGroup

		// 启动多个协程处理文件中的每一行
		for _, Target := range get_targets().Targets {
			// 每启动一个协程，增加 WaitGroup 的计数器
			wg.Add(1)
			configuration(Target.TargetId, Target.Address)
			go add_scan(Target.TargetId, &wg)
			fmt.Println(Target.Address, " 已加入扫描列表")
		}

		// 等待所有协程完成
		wg.Wait()

	} else {
		start_scan()
	}

}

func checkAuthentication() bool {

	url := awvsURL + "/api/v1/targets"
	// 创建 HTTP 请求对象
	req, err := http.NewRequest("GET", url, nil)
	// 设置请求的自定义 Header
	req.Header = headers
	// 创建 HTTP 客户端，并使用自定义 Transport
	client := &http.Client{Transport: ssl}
	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("初始化失败，请检查AWVS URL是否正确")
		return false
	}
	// 关闭 HTTP 响应体的连接，以释放资源和避免资源泄漏。
	defer resp.Body.Close()
	// 判断是否为401
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("AWVS认证失败，请检查API密钥是否正确")
		return false
	}

	return true
}

func add_target(target string, wg *sync.WaitGroup) {

	// 设置请求地址
	url := awvsURL + "/api/v1/targets"

	// 创建 JSON 数据
	data := map[string]string{
		"address":     target,
		"description": description,
		"criticality": "10",
	}

	// 将 JSON 数据编码为字节切片
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("JSON 编码失败:", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求失败:", err)
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
	}
	defer resp.Body.Close()
	// 处理响应
	if resp.StatusCode != 201 {
		fmt.Println("POST 请求失败，状态码:", resp.StatusCode)
	}
	//获取返回的数据
	respData, _ := io.ReadAll(resp.Body)
	//编写返回的结构体
	type ResponseData struct {
		TargetID string `json:"target_id"`
	}
	//解析json
	var tarid ResponseData
	err = json.Unmarshal(respData, &tarid)
	configuration(tarid.TargetID, target)
	if istoscan == 1 {
		add_scan(tarid.TargetID, wg)
		fmt.Println("已添加扫描任务:", target)
	} else {
		defer wg.Done()
		fmt.Println("已添加目标:", target)
	}

}

func add_scan(targetid string, wg *sync.WaitGroup) bool {
	defer wg.Done()

	// 设置请求地址
	url := awvsURL + "/api/v1/scans"
	//json内容
	postdata := map[string]interface{}{
		"target_id":  targetid,
		"profile_id": profileID,
		"schedule": map[string]interface{}{
			"disable":        false,
			"start_date":     nil,
			"time_sensitive": false,
		},
	}
	// 将 JSON 数据编码为字节切片
	jsonData, err := json.Marshal(postdata)
	if err != nil {
		fmt.Println("JSON 编码失败:", err)
		return false
	}
	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return false
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return false
	}
	defer resp.Body.Close()

	// 处理响应
	if resp.StatusCode != 201 {
		fmt.Println("请求失败:", resp.Status)
		return false
	}
	return true
}

func get_targets() ResponseData {
	// 设置请求地址
	url := awvsURL + "/api/v1/targets"
	// 创建 HTTP 请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
	}
	defer resp.Body.Close()

	// 处理响应

	var tardata ResponseData
	ByteResult, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(ByteResult, &tardata)
	if err != nil {
		fmt.Println("JSON 解码失败:", err)
	}
	return tardata

}

func del_targets() bool {
	// 使用 WaitGroup 来等待所有协程完成
	var wg sync.WaitGroup

	// 启动多个协程处理文件中的每一行
	for _, Target := range get_targets().Targets {
		// 每启动一个协程，增加 WaitGroup 的计数器
		wg.Add(1)
		go del_target(Target.TargetId, Target.Address, &wg)
	}

	// 等待所有协程完成
	wg.Wait()
	return true
}

func del_target(targetid, target_adr string, wg *sync.WaitGroup) bool {
	defer wg.Done()
	// 设置请求地址
	url := awvsURL + "/api/v1/targets/" + targetid

	// 创建 HTTP 请求
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
	}
	defer resp.Body.Close()
	// 处理响应
	if resp.StatusCode != 204 {
		fmt.Println("删除目标失败，状态码:", resp.StatusCode)
	} else {
		fmt.Println(target_adr, " 已删除成功")
	}
	return true
}

func del_task(scan_id string, address string, wg *sync.WaitGroup) bool {
	defer wg.Done()
	// 设置请求地址
	url := awvsURL + "/api/v1/scans/" + scan_id
	// 创建 HTTP 请求
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
	}
	defer resp.Body.Close()

	// 处理响应
	if resp.StatusCode == 204 {
		fmt.Println(address, " 任务删除成功")
	} else {
		fmt.Println("删除任务失败，状态码:", resp.StatusCode)
	}
	return true

}

func del_tasks() bool {

	// 设置请求地址
	url := awvsURL + "/api/v1/scans"
	// 创建 HTTP 请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
	}
	// 设置请求的自定义 Header
	req.Header = headers
	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
	}
	defer resp.Body.Close()
	type ScanTask struct {
		ScanID string `json:"scan_id"`
		Target struct {
			Address string `json:"address"`
		} `json:"target"`
	}

	type ScanTasksResult struct {
		Scans []ScanTask `json:"scans"`
	}

	// 处理响应
	var scanData ScanTasksResult
	ByteResult, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(ByteResult, &scanData)
	if err != nil {
		fmt.Println("JSON 解码失败:", err)
	}

	// 使用 WaitGroup 来等待所有协程完成
	var wg sync.WaitGroup

	// 启动多个协程处理文件中的每一行
	for _, scan := range scanData.Scans {
		// 每启动一个协程，增加 WaitGroup 的计数器
		wg.Add(1)
		go del_task(scan.ScanID, scan.Target.Address, &wg)
	}

	// 等待所有协程完成
	wg.Wait()

	return true
}

func customLog4j() string {
	getTargetURL := awvsURL + "/api/v1/scanning_profiles"

	// 构造 POST 请求的数据
	postData := map[string]interface{}{
		"name":   "Apache Log4j RCE",
		"custom": true,
		"checks": []string{"wvs/Scripts/PerFile", "wvs/Scripts/PerFolder", "wvs/Scripts/PerScheme/ASP_Code_Injection.script", "wvs/Scripts/PerScheme/PHP_Deserialization_Gadgets.script", "wvs/Scripts/PerScheme/Arbitrary_File_Creation.script", "wvs/Scripts/PerScheme/Arbitrary_File_Deletion.script", "wvs/Scripts/PerScheme/Blind_XSS.script", "wvs/Scripts/PerScheme/CRLF_Injection.script", "wvs/Scripts/PerScheme/Code_Execution.script", "wvs/Scripts/PerScheme/Directory_Traversal.script", "wvs/Scripts/PerScheme/Email_Header_Injection.script", "wvs/Scripts/PerScheme/Email_Injection.script", "wvs/Scripts/PerScheme/Error_Message.script", "wvs/Scripts/PerScheme/Expression_Language_Injection.script", "wvs/Scripts/PerScheme/File_Inclusion.script", "wvs/Scripts/PerScheme/File_Tampering.script", "wvs/Scripts/PerScheme/File_Upload.script", "wvs/Scripts/PerScheme/Generic_Oracle_Padding.script", "wvs/Scripts/PerScheme/HTTP_Parameter_Pollution.script", "wvs/Scripts/PerScheme/Host_Based_Attack_Reset_Password.script", "wvs/Scripts/PerScheme/LDAP_Injection.script", "wvs/Scripts/PerScheme/Long_Password_Denial_of_Service.script", "wvs/Scripts/PerScheme/MongoDB_Injection.script", "wvs/Scripts/PerScheme/NodeJs_Injection.script", "wvs/Scripts/PerScheme/PHP_Code_Injection.script", "wvs/Scripts/PerScheme/RubyOnRails_Code_Injection.script", "wvs/Scripts/PerScheme/Perl_Code_Injection.script", "wvs/Scripts/PerScheme/PHP_User_Controlled_Vulns.script", "wvs/Scripts/PerScheme/Rails_Mass_Assignment.script", "wvs/Scripts/PerScheme/Rails_Where_SQL_Injection.script", "wvs/Scripts/PerScheme/Rails_render_inline_RCE.script", "wvs/Scripts/PerScheme/Remote_File_Inclusion_XSS.script", "wvs/Scripts/PerScheme/Script_Source_Code_Disclosure.script", "wvs/Scripts/PerScheme/Server_Side_Request_Forgery.script", "wvs/Scripts/PerScheme/Sql_Injection.script", "wvs/Scripts/PerScheme/Struts_RCE_S2-053_CVE-2017-12611.script", "wvs/Scripts/PerScheme/Struts_RCE_S2_029.script", "wvs/Scripts/PerScheme/Unsafe_preg_replace.script", "wvs/Scripts/PerScheme/XFS_and_Redir.script", "wvs/Scripts/PerScheme/XML_External_Entity_Injection.script", "wvs/Scripts/PerScheme/XPath_Injection.script", "wvs/Scripts/PerScheme/XSS.script", "wvs/Scripts/PerScheme/ESI_Injection.script", "wvs/Scripts/PerScheme/Java_Deserialization.script", "wvs/Scripts/PerScheme/Pickle_Serialization.script", "wvs/Scripts/PerScheme/Python_Code_Injection.script", "wvs/Scripts/PerScheme/Argument_Injection.script", "wvs/Scripts/PerScheme/DotNet_BinaryFormatter_Deserialization.script", "wvs/Scripts/PerScheme/Apache_Solr_Parameter_Injection.script", "wvs/Scripts/PerScheme/Cmd_Hijack_Windows.script", "wvs/Scripts/PerScheme/JWT_Param_Audit.script", "wvs/Scripts/PerServer", "wvs/Scripts/PostCrawl", "wvs/Scripts/PostScan", "wvs/Scripts/WebApps", "wvs/RPA", "wvs/Crawler", "wvs/httpdata", "wvs/target/rails_sprockets_path_traversal.js", "wvs/target/web_cache_poisoning.js", "wvs/target/aux_systems_ssrf.js", "wvs/target/proxy_misrouting_ssrf.js", "wvs/target/http_01_ACME_challenge_xss.js", "wvs/target/java_melody_detection_plus_xxe.js", "wvs/target/uwsgi_path_traversal.js", "wvs/target/weblogic_rce_CVE-2018-3245.js", "wvs/target/php_xdebug_rce.js", "wvs/target/nginx_integer_overflow_CVE-2017-7529.js", "wvs/target/jupyter_notebook_rce.js", "wvs/target/hadoop_yarn_resourcemanager.js", "wvs/target/couchdb_rest_api.js", "wvs/target/activemq_default_credentials.js", "wvs/target/apache_mod_jk_access_control_bypass.js", "wvs/target/mini_httpd_file_read_CVE-2018-18778.js", "wvs/target/osgi_management_console_default_creds.js", "wvs/target/docker_engine_API_exposed.js", "wvs/target/docker_registry_API_exposed.js", "wvs/target/jenkins_audit.js", "wvs/target/thinkphp_5_0_22_rce.js", "wvs/target/uwsgi_unauth.js", "wvs/target/fastcgi_unauth.js", "wvs/target/apache_balancer_manager.js", "wvs/target/cisco_ise_stored_xss.js", "wvs/target/horde_imp_rce.js", "wvs/target/nagiosxi_556_rce.js", "wvs/target/next_js_arbitrary_file_read.js", "wvs/target/php_opcache_status.js", "wvs/target/opencms_solr_xxe.js", "wvs/target/redis_open.js", "wvs/target/memcached_open.js", "wvs/target/Weblogic_async_rce_CVE-2019-2725.js", "wvs/target/Weblogic_T3_XXE_CVE-2019-2647.js", "wvs/target/RevProxy_Detection.js", "wvs/target/cassandra_open.js", "wvs/target/nagiosxi_sqli_CVE-2018-8734.js", "wvs/target/backdoor_bootstrap_sass.js", "wvs/target/apache_spark_audit.js", "wvs/target/fortigate_file_reading.js", "wvs/target/pulse_sslvpn_file_reading.js", "wvs/target/SAP_Hybris_virtualjdbc_RCE_CVE-2019-0344.js", "wvs/target/webmin_rce_1_920_CVE-2019-15107.js", "wvs/target/Weblogic_T3_XXE_CVE-2019-2888.js", "wvs/target/citrix_netscaler_CVE-2019-19781.js", "wvs/target/DotNet_HTTP_Remoting.js", "wvs/target/opensearch-target.js", "wvs/target/adminer-4.6.2-file-disclosure-vulnerability.js", "wvs/target/apache_mod_rewrite_open_redirect_CVE-2019-10098.js", "wvs/target/default_apple-app-site-association.js", "wvs/target/golang-debug-pprof.js", "wvs/target/openid_connect_discovery.js", "wvs/target/nginx-plus-unprotected-status.js", "wvs/target/nginx-plus-unprotected-api.js", "wvs/target/nginx-plus-unprotected-dashboard.js", "wvs/target/nginx-plus-unprotected-upstream.js", "wvs/target/Kentico_CMS_Audit.js", "wvs/target/Rails_DoubleTap_RCE_CVE-2019-5418.js", "wvs/target/Oracle_EBS_Audit.js", "wvs/target/rce_sql_server_reporting_services.js", "wvs/target/liferay_portal_jsonws_rce.js", "wvs/target/php_opcache_gui.js", "wvs/target/check_acumonitor.js", "wvs/target/spring_cloud_config_server_CVE-2020-5410.js", "wvs/target/f5_big_ip_tmui_rce_CVE-2020-5902.js", "wvs/target/rack_mini_profiler_information_disclosure.js", "wvs/target/grafana_ssrf_rce_CVE-2020-13379.js", "wvs/target/h2-console.js", "wvs/target/jolokia_xxe.js", "wvs/target/rails_rce_locals_CVE-2020-8163.js", "wvs/target/Cisco_ASA_Path_Traversal_CVE-2020-3452.js", "wvs/target/DNN_Deser_Cookie_CVE-2017-9822.js", "wvs/target/404_text_search.js", "wvs/target/totaljs_dir_traversal_CVE-2019-8903.js", "wvs/target/OFBiz_xmlrpc_deser_rce_CVE-2020-9496.js", "wvs/target/http_redirections.js", "wvs/target/apache_zookeeper_open.js", "wvs/target/apache_kafka_open.js", "wvs/target/nette_framework_rce_CVE-2020-15227.js", "wvs/target/vmware_vcenter_unauth_file_read.js", "wvs/target/mobile_iron_rce_CVE-2020-15505.js", "wvs/target/web_cache_poisoning_dos.js", "wvs/target/prototype_pollution_target.js", "wvs/target/openfire_admin_console_ssrf_CVE-2019-18394.js", "wvs/target/weblogic_rce_CVE-2020-14882.js", "wvs/target/Weblogic_IIOP_RCE_CVE-2020-2551.js", "wvs/target/Odoo_audit.js", "wvs/target/citrix_xenmobile_arbitrary_file_read_CVE-2020-8209.js", "wvs/target/sonarqube_default_credentials.js", "wvs/target/common_api_endpoints.js", "wvs/target/Unomi_MVEL_RCE_CVE-2020-13942.js", "wvs/target/symfony_weak_secret_rce.js", "wvs/target/lucee_arbitrary_file_write.js", "wvs/target/dynamic_rendering_engines.js", "wvs/target/open_prometheus.js", "wvs/target/open_monitoring.js", "wvs/target/apache_flink_path_traversal_CVE-2020-17519.js", "wvs/target/imageresizer_debug.js", "wvs/target/unprotected_apache_nifi.js", "wvs/target/unprotected_kong_gateway_adminapi_interface.js", "wvs/target/sap_solution_manager_rce_CVE-2020-6207.js", "wvs/target/sonicwall_ssl_vpn_rce_jarrewrite.js", "wvs/target/nodejs_debugger_open.js", "wvs/target/vmware_vcenter_server_unauth_rce_CVE-2021-21972.js", "wvs/target/paloalto-pan-os-xss-CVE-2020-2036.js", "wvs/target/golang_delve_debugger_open.js", "wvs/target/microsoft_exchange-server-ssrf-CVE-2021-26855.js", "wvs/target/python_debugpy_debugger_open.js", "wvs/target/AppWeb_auth_bypass_CVE-2018-8715.js", "wvs/target/OFBiz_SOAPService_deser_rce_CVE-2021-26295.js", "wvs/target/vhost_files_locs_misconfig.js", "wvs/target/cockpit_nosqli_CVE-2020-35847.js", "wvs/target/f5_iControl_REST_RCE_CVE-2021-22986.js", "wvs/target/Cisco_RV_auth_bypass_CVE-2021-1472.js", "wvs/target/web_installer_exposed.js", "wvs/target/ntopng_auth_bypass_CVE-2021-28073.js", "wvs/target/request_smuggling.js", "wvs/target/Hashicorp_Consul_exposed.js", "wvs/target/django_debug_toolbar.js", "wvs/target/VMware_vRealize_SSRF_CVE-2021-21975.js", "wvs/target/GravCMS_unauth_RCE_CVE-2021-21425.js", "wvs/target/caddy_unprotected_api.js", "wvs/target/dragonfly_arbitrary_file_read_CVE-2021-33564.js", "wvs/target/bitrix_audit.js", "wvs/target/open_redirect.js", "wvs/target/gitlab_audit.js", "wvs/target/nacos_auth_bypass_CVE-2021-29441.js", "wvs/target/sap_bo_bip_ssrf_CVE-2020-6308.js", "wvs/target/detect_apache_shiro_server.js", "wvs/target/jetty_concat_inf_disc_CVE-2021-28164.js", "wvs/target/RethinkDB_open.js", "wvs/target/spring_boot_actuator_logview_path_trav_CVE-2021-21234.js", "wvs/target/open_webpagetest.js", "wvs/target/buddypress_rest_api_privesc_CVE-2021-21389.js", "wvs/target/Hasura_GraphQL_SSRF.js", "wvs/target/grandnode_path_traversal_CVE-2019-12276.js", "wvs/target/SearchBlox_File_Inclusion_CVE-2020-35580.js", "wvs/target/Zimbra_SSRF_CVE-2020-7796.js", "wvs/target/jetty_inf_disc_CVE-2021-34429.js", "wvs/target/Cisco_ASA_XSS_CVE-2020-3580.js", "wvs/target/haproxy_unprotected_api.js", "wvs/target/kong_unprotected_api.js", "wvs/target/OData_feed_accessible_anonymously.js", "wvs/target/Confluence_OGNL_Injection_CVE-2021-26084.js", "wvs/target/microsoft_exchange_preauth_path_confusion_CVE-2021-34473.js", "wvs/target/Atlassian_Jira_File_Read_CVE-2021-26086.js", "wvs/target/ManageEngine_ADSelfService_Plus_auth_bypass_CVE-2021-40539.js", "wvs/target/Django_Debug_Mode.js", "wvs/target/Payara_Micro_File_Read_CVE-2021-41381.js", "wvs/target/keycloak_request_uri_SSRF_CVE-2020-10770.js", "wvs/target/apache_mod_proxy_SSRF_CVE-2021-40438.js", "wvs/target/apache_insecure_path_norm_CVE-2021-41773_CVE-2021-42013.js", "wvs/target/gitlab_exiftool_rce_CVE-2021-22205.js", "wvs/target/http2/http2_pseudo_header_ssrf.js", "wvs/target/Sitecore_XP_RCE_CVE-2021-42237.js", "wvs/target/http2/http2_misrouting_ssrf.js", "wvs/target/http2/http2_web_cache_poisoning.js", "wvs/target/http2/http2_web_cache_poisoning_dos.js", "wvs/input_group", "wvs/deepscan", "wvs/custom-scripts", "wvs/MalwareScanner", "wvs/location/zabbix/zabbix_audit.js", "wvs/location/reverse_proxy_path_traversal.js", "wvs/location/cors_origin_validation.js", "wvs/location/yii2/yii2_gii.js", "wvs/location/nodejs_source_code_disclosure.js", "wvs/location/npm_debug_log.js", "wvs/location/php_cs_cache.js", "wvs/location/laravel_log_viewer_lfd.js", "wvs/location/sap_b2b_lfi.js", "wvs/location/nodejs_path_traversal_CVE-2017-14849.js", "wvs/location/jquery_file_upload_rce.js", "wvs/location/goahead_web_server_rce.js", "wvs/location/file_upload_via_put_method.js", "wvs/location/coldfusion/coldfusion_rds_login.js", "wvs/location/coldfusion/coldfusion_request_debugging.js", "wvs/location/coldfusion/coldfusion_robust_exception.js", "wvs/location/coldfusion/coldfusion_add_paths.js", "wvs/location/coldfusion/coldfusion_amf_deser.js", "wvs/location/coldfusion/coldfusion_jndi_inj_rce.js", "wvs/location/coldfusion/coldfusion_file_uploading_CVE-2018-15961.js", "wvs/location/python_source_code_disclosure.js", "wvs/location/ruby_source_code_disclosure.js", "wvs/location/confluence/confluence_widget_SSTI_CVE-2019-3396.js", "wvs/location/shiro/apache-shiro-deserialization-rce.js", "wvs/location/coldfusion/coldfusion_flashgateway_deser_CVE-2019-7091.js", "wvs/location/oraclebi/oracle_biee_convert_xxe_CVE-2019-2767.js", "wvs/location/oraclebi/oracle_biee_adfresource_dirtraversal_CVE-2019-2588.js", "wvs/location/oraclebi/oracle_biee_authbypass_CVE-2019-2768.js", "wvs/location/oraclebi/oracle_biee_ReportTemplateService_xxe_CVE-2019-2616.js", "wvs/location/oraclebi/oracle_biee_default_creds.js", "wvs/location/hidden_parameters.js", "wvs/location/asp_net_resolveurl_xss.js", "wvs/location/oraclebi/oracle_biee_amf_deser_rce_CVE-2020-2950.js", "wvs/location/composer_installed_json.js", "wvs/location/typo3/typo3_audit.js", "wvs/location/config_json_files_secrets_leakage.js", "wvs/location/import_swager_files_from_common_locations.js", "wvs/location/forgerock/forgerock_openam_deser_rce_CVE-2021-35464.js", "wvs/location/web_cache_poisoning_dos_for_js.js", "wvs/location/forgerock/forgerock_openam_ldap_inj_CVE-2021-29156.js", "wvs/location/ghost/Ghost_Theme_Preview_XSS_CVE-2021-29484.js", "wvs/location/qdpm/qdPM_Inf_Disclosure.js", "wvs/location/apache_source_code_disclosure.js", "wvs/location/oraclebi/oracle_biee_ReportTemplateService_xxe_CVE-2021-2400.js", "ovas/"},
	}

	postDataJSON, err := json.Marshal(postData)
	if err != nil {
		fmt.Println("JSON 编码失败:", err)
		return ""
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", getTargetURL, bytes.NewBuffer(postDataJSON))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 获取配置信息
	getTargetURL = awvsURL + "/api/v1/scanning_profiles"

	// 创建 HTTP 请求
	req, err = http.NewRequest("GET", getTargetURL, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client = &http.Client{Transport: ssl}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 读取响应内容
	var responseJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseJSON); err != nil {
		fmt.Println("JSON 解码失败:", err)
		return ""
	}

	// 检查是否包含 "Apache Log4j RCE" 的扫描配置
	for _, profile := range responseJSON["scanning_profiles"].([]interface{}) {

		profileMap := profile.(map[string]interface{})

		if profileMap["name"].(string) == "Apache Log4j RCE" {
			profileID := profileMap["profile_id"].(string)
			return profileID
		}
	}

	fmt.Println("未找到 Apache Log4j RCE 的扫描配置")
	return ""
}

func custom_bug_bounty() string {
	getTargetURL := awvsURL + "/api/v1/scanning_profiles"

	// 构造 POST 请求的数据
	postData := map[string]interface{}{
		"name":   "Bug Bounty",
		"custom": true,
		"checks": []string{"wvs/Crawler", "wvs/deepscan", "wvs/custom-scripts", "wvs/MalwareScanner", "wvs/Scripts/PerFile/Backup_File.script", "wvs/Scripts/PerFile/Bash_RCE.script", "wvs/Scripts/PerFile/HTML_Form_In_Redirect_Page.script", "wvs/Scripts/PerFile/Hashbang_Ajax_Crawling.script", "wvs/Scripts/PerFile/Javascript_AST_Parse.script", "wvs/Scripts/PerFile/Javascript_Libraries_Audit.script", "wvs/Scripts/PerFile/PHP_SuperGlobals_Overwrite.script", "wvs/Scripts/PerFile/REST_Discovery_And_Audit_File.script", "wvs/Scripts/PerFolder/APC.script", "wvs/Scripts/PerFolder/ASP-NET_Application_Trace.script", "wvs/Scripts/PerFolder/ASP-NET_Debugging_Enabled.script", "wvs/Scripts/PerFolder/ASP-NET_Diagnostic_Page.script", "wvs/Scripts/PerFolder/Access_Database_Found.script", "wvs/Scripts/PerFolder/Apache_Solr.script", "wvs/Scripts/PerFolder/Backup_Folder.script", "wvs/Scripts/PerFolder/Basic_Auth_Over_HTTP.script", "wvs/Scripts/PerFolder/Bazaar_Repository.script", "wvs/Scripts/PerFolder/CVS_Repository.script", "wvs/Scripts/PerFolder/Core_Dump_Files.script", "wvs/Scripts/PerFolder/Development_Files.script", "wvs/Scripts/PerFolder/Dreamweaver_Scripts.script", "wvs/Scripts/PerFolder/GIT_Repository.script", "wvs/Scripts/PerFolder/Grails_Database_Console.script", "wvs/Scripts/PerFolder/HTML_Form_In_Redirect_Page_Dir.script", "wvs/Scripts/PerFolder/Http_Verb_Tampering.script", "wvs/Scripts/PerFolder/IIS51_Directory_Auth_Bypass.script", "wvs/Scripts/PerFolder/JetBrains_Idea_Project_Directory.script", "wvs/Scripts/PerFolder/Mercurial_Repository.script", "wvs/Scripts/PerFolder/Possible_Sensitive_Directories.script", "wvs/Scripts/PerFolder/Possible_Sensitive_Files.script", "wvs/Scripts/PerFolder/REST_Discovery_And_Audit_Folder.script", "wvs/Scripts/PerFolder/Readme_Files.script", "wvs/Scripts/PerFolder/SFTP_Credentials_Exposure.script", "wvs/Scripts/PerFolder/SQL_Injection_In_Basic_Auth.script", "wvs/Scripts/PerFolder/Trojan_Scripts.script", "wvs/Scripts/PerFolder/WS_FTP_log_file.script", "wvs/Scripts/PerFolder/Webadmin_script.script", "wvs/Scripts/PerFolder/htaccess_File_Readable.script", "wvs/Scripts/PerFolder/Deadjoe_file.script", "wvs/Scripts/PerFolder/Symfony_Databases_YML.script", "wvs/Scripts/PerFolder/dotenv_File.script", "wvs/Scripts/PerFolder/Spring_Boot_WhiteLabel_Error_Page_SPEL.script", "wvs/Scripts/PerFolder/Nginx_Path_Traversal_Misconfigured_Alias.script", "wvs/Scripts/PerFolder/Spring_Security_Auth_Bypass_CVE-2016-5007.script", "wvs/Scripts/PerScheme/ASP_Code_Injection.script", "wvs/Scripts/PerScheme/PHP_Deserialization_Gadgets.script", "wvs/Scripts/PerScheme/Email_Header_Injection.script", "wvs/Scripts/PerScheme/Email_Injection.script", "wvs/Scripts/PerScheme/Error_Message.script", "wvs/Scripts/PerScheme/Expression_Language_Injection.script", "wvs/Scripts/PerScheme/Generic_Oracle_Padding.script", "wvs/Scripts/PerScheme/Host_Based_Attack_Reset_Password.script", "wvs/Scripts/PerScheme/LDAP_Injection.script", "wvs/Scripts/PerScheme/Long_Password_Denial_of_Service.script", "wvs/Scripts/PerScheme/MongoDB_Injection.script", "wvs/Scripts/PerScheme/NodeJs_Injection.script", "wvs/Scripts/PerScheme/PHP_Code_Injection.script", "wvs/Scripts/PerScheme/RubyOnRails_Code_Injection.script", "wvs/Scripts/PerScheme/Perl_Code_Injection.script", "wvs/Scripts/PerScheme/PHP_User_Controlled_Vulns.script", "wvs/Scripts/PerScheme/Rails_Mass_Assignment.script", "wvs/Scripts/PerScheme/Rails_Where_SQL_Injection.script", "wvs/Scripts/PerScheme/Rails_render_inline_RCE.script", "wvs/Scripts/PerScheme/Unsafe_preg_replace.script", "wvs/Scripts/PerScheme/XFS_and_Redir.script", "wvs/Scripts/PerScheme/XPath_Injection.script", "wvs/Scripts/PerScheme/ESI_Injection.script", "wvs/Scripts/PerScheme/Java_Deserialization.script", "wvs/Scripts/PerScheme/Pickle_Serialization.script", "wvs/Scripts/PerScheme/Python_Code_Injection.script", "wvs/Scripts/PerScheme/DotNet_BinaryFormatter_Deserialization.script", "wvs/Scripts/PerScheme/Apache_Solr_Parameter_Injection.script", "wvs/Scripts/PerScheme/Cmd_Hijack_Windows.script", "wvs/Scripts/WebApps", "wvs/Scripts/PerScheme/HTTP_Parameter_Pollution.script", "wvs/Scripts/PerServer/AJP_Audit.script", "wvs/Scripts/PerServer/ASP_NET_Error_Message.script", "wvs/Scripts/PerServer/ASP_NET_Forms_Authentication_Bypass.script", "wvs/Scripts/PerServer/Apache_Proxy_CONNECT_Enabled.script", "wvs/Scripts/PerServer/Apache_Roller_Audit.script", "wvs/Scripts/PerServer/Apache_Running_As_Proxy.script", "wvs/Scripts/PerServer/Apache_Server_Information.script", "wvs/Scripts/PerServer/Apache_XSS_via_Malformed_Method.script", "wvs/Scripts/PerServer/Apache_httpOnly_Cookie_Disclosure.script", "wvs/Scripts/PerServer/Apache_mod_negotiation_Filename_Bruteforcing.script", "wvs/Scripts/PerServer/Barracuda_locale_Directory_Traversal.script", "wvs/Scripts/PerServer/Bash_RCE_Server_Audit.script", "wvs/Scripts/PerServer/ColdFusion_Audit.script", "wvs/Scripts/PerServer/ColdFusion_User_Agent_XSS.script", "wvs/Scripts/PerServer/ColdFusion_v8_File_Upload.script", "wvs/Scripts/PerServer/ColdFusion_v9_Solr_Exposed.script", "wvs/Scripts/PerServer/CoreDumpCheck.script", "wvs/Scripts/PerServer/Error_Page_Path_Disclosure.script", "wvs/Scripts/PerServer/Frontpage_Extensions_Enabled.script", "wvs/Scripts/PerServer/Frontpage_Information.script", "wvs/Scripts/PerServer/Frontpage_authors_pwd.script", "wvs/Scripts/PerServer/GlassFish_41_Directory_Traversal.script", "wvs/Scripts/PerServer/GlassFish_Audit.script", "wvs/Scripts/PerServer/Hadoop_Cluster_Web_Interface.script", "wvs/Scripts/PerServer/Horde_IMP_Webmail_Exploit.script", "wvs/Scripts/PerServer/IBM_WCM_XPath_Injection.script", "wvs/Scripts/PerServer/IBM_WebSphere_Audit.script", "wvs/Scripts/PerServer/IIS_Global_Asa.script", "wvs/Scripts/PerServer/IIS_Internal_IP_Address.script", "wvs/Scripts/PerServer/IIS_Unicode_Directory_Traversal.script", "wvs/Scripts/PerServer/IIS_service_cnf.script", "wvs/Scripts/PerServer/IIS_v5_NTML_Basic_Auth_Bypass.script", "wvs/Scripts/PerServer/Ioncube_Loader_Wizard.script", "wvs/Scripts/PerServer/JBoss_Audit.script", "wvs/Scripts/PerServer/JBoss_Status_Servlet_Information_Leak.script", "wvs/Scripts/PerServer/JBoss_Web_Service_Console.script", "wvs/Scripts/PerServer/JMX_RMI_service.script", "wvs/Scripts/PerServer/Java_Application_Servers_Fuzz.script", "wvs/Scripts/PerServer/Java_Debug_Wire_Protocol_Audit.script", "wvs/Scripts/PerServer/Jetty_Audit.script", "wvs/Scripts/PerServer/Lotus_Domino_crlf_xss.script", "wvs/Scripts/PerServer/Misfortune_Cookie.script", "wvs/Scripts/PerServer/MongoDB_Audit.script", "wvs/Scripts/PerServer/Movable_Type_4_RCE.script", "wvs/Scripts/PerServer/Nginx_PHP_FastCGI_Code_Execution_File_Upload.script", "wvs/Scripts/PerServer/Oracle_Application_Logs.script", "wvs/Scripts/PerServer/Oracle_Reports_Audit.script", "wvs/Scripts/PerServer/PHP_CGI_RCE_Force_Redirect.script", "wvs/Scripts/PerServer/PHP_Hash_Collision_Denial_Of_Service.script", "wvs/Scripts/PerServer/Parallels_Plesk_Audit.script", "wvs/Scripts/PerServer/Plesk_Agent_SQL_Injection.script", "wvs/Scripts/PerServer/Plesk_SSO_XXE.script", "wvs/Scripts/PerServer/Plone&Zope_Remote_Command_Execution.script", "wvs/Scripts/PerServer/Pyramid_Debug_Mode.script", "wvs/Scripts/PerServer/Railo_Audit.script", "wvs/Scripts/PerServer/Reverse_Proxy_Bypass.script", "wvs/Scripts/PerServer/RubyOnRails_Database_File.script", "wvs/Scripts/PerServer/SSL_Audit.script", "wvs/Scripts/PerServer/Same_Site_Scripting.script", "wvs/Scripts/PerServer/Snoop_Servlet.script", "wvs/Scripts/PerServer/Tomcat_Audit.script", "wvs/Scripts/PerServer/Tomcat_Examples.script", "wvs/Scripts/PerServer/Tomcat_Hello_JSP_XSS.script", "wvs/Scripts/PerServer/Tomcat_Status_Page.script", "wvs/Scripts/PerServer/Tornado_Debug_Mode.script", "wvs/Scripts/PerServer/Track_Trace_Server_Methods.script", "wvs/Scripts/PerServer/Unprotected_phpMyAdmin_Interface.script", "wvs/Scripts/PerServer/VMWare_Directory_Traversal.script", "wvs/Scripts/PerServer/Version_Check.script", "wvs/Scripts/PerServer/VirtualHost_Audit.script", "wvs/Scripts/PerServer/WAF_Detection.script", "wvs/Scripts/PerServer/WEBrick_Directory_Traversal.script", "wvs/Scripts/PerServer/WebLogic_Audit.script", "wvs/Scripts/PerServer/Web_Server_Default_Welcome_Page.script", "wvs/Scripts/PerServer/Web_Statistics.script", "wvs/Scripts/PerServer/XML_External_Entity_Injection_Server.script", "wvs/Scripts/PerServer/Zend_Framework_Config_File.script", "wvs/Scripts/PerServer/elasticsearch_Audit.script", "wvs/Scripts/PerServer/elmah_Information_Disclosure.script", "wvs/Scripts/PerServer/lighttpd_v1434_Sql_Injection.script", "wvs/Scripts/PerServer/ms12-050.script", "wvs/Scripts/PerServer/phpMoAdmin_Remote_Code_Execution.script", "wvs/Scripts/PerServer/Weblogic_wls-wsat_RCE.script", "wvs/Scripts/PerServer/phpunit_RCE_CVE-2017-9841.script", "wvs/Scripts/PerServer/Atlassian_OAuth_Plugin_IconUriServlet_SSRF.script", "wvs/Scripts/PerServer/PHP_FPM_Status_Page.script", "wvs/Scripts/PerServer/Test_CGI_Script.script", "wvs/Scripts/PerServer/Cisco_ASA_Path_Traversal_CVE-2018-0296.script", "wvs/Scripts/PerServer/JBoss_RCE_CVE-2015-7501.script", "wvs/Scripts/PerServer/JBoss_RCE_CVE-2017-7504.script", "wvs/Scripts/PerServer/WebSphere_RCE_CVE-2015-7450.script", "wvs/Scripts/PerServer/Liferay_RCE_tra-2017-01.script", "wvs/Scripts/PerServer/Liferay_Xmlrpc_SSRF.script", "wvs/Scripts/PostCrawl/Adobe_Flex_Audit.script", "wvs/Scripts/PostCrawl/Amazon_S3_Buckets_Audit.script", "wvs/Scripts/PostCrawl/Apache_CN_Discover_New_Files.script", "wvs/Scripts/PostCrawl/Azure_Blobs_Audit.script", "wvs/Scripts/PostCrawl/CKEditor_Audit.script", "wvs/Scripts/PostCrawl/CakePHP_Audit.script", "wvs/Scripts/PostCrawl/Config_File_Disclosure.script", "wvs/Scripts/PostCrawl/ExtJS_Examples_Arbitrary_File_Read.script", "wvs/Scripts/PostCrawl/FCKEditor_Audit.script", "wvs/Scripts/PostCrawl/GWT_Audit.script", "wvs/Scripts/PostCrawl/Genericons_Audit.script", "wvs/Scripts/PostCrawl/IIS_Tilde_Dir_Enumeration.script", "wvs/Scripts/PostCrawl/J2EE_Audit.script", "wvs/Scripts/PostCrawl/JAAS_Authentication_Bypass.script", "wvs/Scripts/PostCrawl/JBoss_Seam_Remoting.script", "wvs/Scripts/PostCrawl/JBoss_Seam_actionOutcome.script", "wvs/Scripts/PostCrawl/JSP_Authentication_Bypass.script", "wvs/Scripts/PostCrawl/MS15-034.script", "wvs/Scripts/PostCrawl/Minify_Audit.script", "wvs/Scripts/PostCrawl/OFC_Upload_Image_Audit.script", "wvs/Scripts/PostCrawl/Oracle_JSF2_Path_Traversal.script", "wvs/Scripts/PostCrawl/PHP_CGI_RCE.script", "wvs/Scripts/PostCrawl/PrimeFaces5_EL_Injection.script", "wvs/Scripts/PostCrawl/Rails_Audit.script", "wvs/Scripts/PostCrawl/Rails_Audit_Routes.script", "wvs/Scripts/PostCrawl/Rails_Devise_Authentication_Password_Reset.script", "wvs/Scripts/PostCrawl/Rails_Weak_secret_token.script", "wvs/Scripts/PostCrawl/Session_Fixation.script", "wvs/Scripts/PostCrawl/SharePoint_Audit.script", "wvs/Scripts/PostCrawl/Struts2_ClassLoader_Manipulation.script", "wvs/Scripts/PostCrawl/Struts2_ClassLoader_Manipulation2.script", "wvs/Scripts/PostCrawl/Struts2_Remote_Code_Execution_S2014.script", "wvs/Scripts/PostCrawl/Timthumb_Audit.script", "wvs/Scripts/PostCrawl/Tiny_MCE_Audit.script", "wvs/Scripts/PostCrawl/Uploadify_Audit.script", "wvs/Scripts/PostCrawl/WADL_Files.script", "wvs/Scripts/PostCrawl/WebDAV_Audit.script", "wvs/Scripts/PostCrawl/XML_Quadratic_Blowup_Attack.script", "wvs/Scripts/PostCrawl/Zend_Framework_LFI_via_XXE.script", "wvs/Scripts/PostCrawl/nginx-redir-headerinjection.script", "wvs/Scripts/PostCrawl/phpLiteAdmin_Audit.script", "wvs/Scripts/PostCrawl/phpThumb_Audit.script", "wvs/Scripts/PostCrawl/tcpdf_Audit.script", "wvs/Scripts/PostScan/10-Webmail_Audit.script", "wvs/Scripts/PostScan/4-Stored_File_Inclusion.script", "wvs/Scripts/PostScan/7-Stored_File_Tampering.script", "wvs/Scripts/PostScan/9-Multiple_Web_Servers.script", "wvs/location/zabbix/zabbix_audit.js", "wvs/location/reverse_proxy_path_traversal.js", "wvs/location/cors_origin_validation.js", "wvs/location/yii2/yii2_gii.js", "wvs/location/nodejs_source_code_disclosure.js", "wvs/location/npm_debug_log.js", "wvs/location/php_cs_cache.js", "wvs/location/laravel_log_viewer_lfd.js", "wvs/location/sap_b2b_lfi.js", "wvs/location/nodejs_path_traversal_CVE-2017-14849.js", "wvs/location/jquery_file_upload_rce.js", "wvs/location/goahead_web_server_rce.js", "wvs/location/file_upload_via_put_method.js", "wvs/location/coldfusion/coldfusion_rds_login.js", "wvs/location/coldfusion/coldfusion_request_debugging.js", "wvs/location/coldfusion/coldfusion_robust_exception.js", "wvs/location/coldfusion/coldfusion_add_paths.js", "wvs/location/coldfusion/coldfusion_amf_deser.js", "wvs/location/coldfusion/coldfusion_jndi_inj_rce.js", "wvs/location/coldfusion/coldfusion_file_uploading_CVE-2018-15961.js", "wvs/location/python_source_code_disclosure.js", "wvs/location/ruby_source_code_disclosure.js", "wvs/location/confluence/confluence_widget_SSTI_CVE-2019-3396.js", "wvs/location/shiro/apache-shiro-deserialization-rce.js", "wvs/location/coldfusion/coldfusion_flashgateway_deser_CVE-2019-7091.js", "wvs/location/oraclebi/oracle_biee_convert_xxe_CVE-2019-2767.js", "wvs/location/oraclebi/oracle_biee_adfresource_dirtraversal_CVE-2019-2588.js", "wvs/location/oraclebi/oracle_biee_authbypass_CVE-2019-2768.js", "wvs/location/oraclebi/oracle_biee_ReportTemplateService_xxe_CVE-2019-2616.js", "wvs/location/oraclebi/oracle_biee_default_creds.js", "wvs/location/asp_net_resolveurl_xss.js", "wvs/location/oraclebi/oracle_biee_amf_deser_rce_CVE-2020-2950.js", "wvs/location/composer_installed_json.js", "wvs/location/typo3/typo3_audit.js", "wvs/location/config_json_files_secrets_leakage.js", "wvs/location/import_swager_files_from_common_locations.js", "wvs/location/forgerock/forgerock_openam_deser_rce_CVE-2021-35464.js", "wvs/location/web_cache_poisoning_dos_for_js.js", "wvs/location/forgerock/forgerock_openam_ldap_inj_CVE-2021-29156.js", "wvs/location/ghost/Ghost_Theme_Preview_XSS_CVE-2021-29484.js", "wvs/location/qdpm/qdPM_Inf_Disclosure.js", "wvs/location/apache_source_code_disclosure.js", "wvs/location/oraclebi/oracle_biee_ReportTemplateService_xxe_CVE-2021-2400.js", "wvs/target/rails_sprockets_path_traversal.js", "wvs/target/proxy_misrouting_ssrf.js", "wvs/target/http_01_ACME_challenge_xss.js", "wvs/target/java_melody_detection_plus_xxe.js", "wvs/target/uwsgi_path_traversal.js", "wvs/target/weblogic_rce_CVE-2018-3245.js", "wvs/target/nginx_integer_overflow_CVE-2017-7529.js", "wvs/target/jupyter_notebook_rce.js", "wvs/target/hadoop_yarn_resourcemanager.js", "wvs/target/couchdb_rest_api.js", "wvs/target/apache_log4j_deser_rce.js", "wvs/target/activemq_default_credentials.js", "wvs/target/apache_mod_jk_access_control_bypass.js", "wvs/target/mini_httpd_file_read_CVE-2018-18778.js", "wvs/target/osgi_management_console_default_creds.js", "wvs/target/docker_engine_API_exposed.js", "wvs/target/docker_registry_API_exposed.js", "wvs/target/jenkins_audit.js", "wvs/target/thinkphp_5_0_22_rce.js", "wvs/target/uwsgi_unauth.js", "wvs/target/fastcgi_unauth.js", "wvs/target/apache_balancer_manager.js", "wvs/target/cisco_ise_stored_xss.js", "wvs/target/horde_imp_rce.js", "wvs/target/nagiosxi_556_rce.js", "wvs/target/next_js_arbitrary_file_read.js", "wvs/target/php_opcache_status.js", "wvs/target/opencms_solr_xxe.js", "wvs/target/redis_open.js", "wvs/target/memcached_open.js", "wvs/target/Weblogic_async_rce_CVE-2019-2725.js", "wvs/target/Weblogic_T3_XXE_CVE-2019-2647.js", "wvs/target/RevProxy_Detection.js", "wvs/target/cassandra_open.js", "wvs/target/nagiosxi_sqli_CVE-2018-8734.js", "wvs/target/backdoor_bootstrap_sass.js", "wvs/target/apache_spark_audit.js", "wvs/target/fortigate_file_reading.js", "wvs/target/pulse_sslvpn_file_reading.js", "wvs/target/SAP_Hybris_virtualjdbc_RCE_CVE-2019-0344.js", "wvs/target/webmin_rce_1_920_CVE-2019-15107.js", "wvs/target/Weblogic_T3_XXE_CVE-2019-2888.js", "wvs/target/citrix_netscaler_CVE-2019-19781.js", "wvs/target/DotNet_HTTP_Remoting.js", "wvs/target/opensearch-target.js", "wvs/target/adminer-4.6.2-file-disclosure-vulnerability.js", "wvs/target/apache_mod_rewrite_open_redirect_CVE-2019-10098.js", "wvs/target/default_apple-app-site-association.js", "wvs/target/golang-debug-pprof.js", "wvs/target/openid_connect_discovery.js", "wvs/target/nginx-plus-unprotected-status.js", "wvs/target/nginx-plus-unprotected-api.js", "wvs/target/nginx-plus-unprotected-dashboard.js", "wvs/target/nginx-plus-unprotected-upstream.js", "wvs/target/Kentico_CMS_Audit.js", "wvs/target/Rails_DoubleTap_RCE_CVE-2019-5418.js", "wvs/target/Oracle_EBS_Audit.js", "wvs/target/rce_sql_server_reporting_services.js", "wvs/target/liferay_portal_jsonws_rce.js", "wvs/target/php_opcache_gui.js", "wvs/target/check_acumonitor.js", "wvs/target/spring_cloud_config_server_CVE-2020-5410.js", "wvs/target/f5_big_ip_tmui_rce_CVE-2020-5902.js", "wvs/target/rack_mini_profiler_information_disclosure.js", "wvs/target/grafana_ssrf_rce_CVE-2020-13379.js", "wvs/target/h2-console.js", "wvs/target/jolokia_xxe.js", "wvs/target/rails_rce_locals_CVE-2020-8163.js", "wvs/target/Cisco_ASA_Path_Traversal_CVE-2020-3452.js", "wvs/target/DNN_Deser_Cookie_CVE-2017-9822.js", "wvs/target/404_text_search.js", "wvs/target/totaljs_dir_traversal_CVE-2019-8903.js", "wvs/target/OFBiz_xmlrpc_deser_rce_CVE-2020-9496.js", "wvs/target/http_redirections.js", "wvs/target/apache_zookeeper_open.js", "wvs/target/apache_kafka_open.js", "wvs/target/nette_framework_rce_CVE-2020-15227.js", "wvs/target/vmware_vcenter_unauth_file_read.js", "wvs/target/mobile_iron_rce_CVE-2020-15505.js", "wvs/target/web_cache_poisoning_dos.js", "wvs/target/prototype_pollution_target.js", "wvs/target/openfire_admin_console_ssrf_CVE-2019-18394.js", "wvs/target/weblogic_rce_CVE-2020-14882.js", "wvs/target/Weblogic_IIOP_RCE_CVE-2020-2551.js", "wvs/target/Odoo_audit.js", "wvs/target/citrix_xenmobile_arbitrary_file_read_CVE-2020-8209.js", "wvs/target/sonarqube_default_credentials.js", "wvs/target/common_api_endpoints.js", "wvs/target/Unomi_MVEL_RCE_CVE-2020-13942.js", "wvs/target/symfony_weak_secret_rce.js", "wvs/target/lucee_arbitrary_file_write.js", "wvs/target/dynamic_rendering_engines.js", "wvs/target/open_prometheus.js", "wvs/target/open_monitoring.js", "wvs/target/apache_flink_path_traversal_CVE-2020-17519.js", "wvs/target/imageresizer_debug.js", "wvs/target/unprotected_apache_nifi.js", "wvs/target/unprotected_kong_gateway_adminapi_interface.js", "wvs/target/sap_solution_manager_rce_CVE-2020-6207.js", "wvs/target/sonicwall_ssl_vpn_rce_jarrewrite.js", "wvs/target/nodejs_debugger_open.js", "wvs/target/vmware_vcenter_server_unauth_rce_CVE-2021-21972.js", "wvs/target/paloalto-pan-os-xss-CVE-2020-2036.js", "wvs/target/golang_delve_debugger_open.js", "wvs/target/microsoft_exchange-server-ssrf-CVE-2021-26855.js", "wvs/target/python_debugpy_debugger_open.js", "wvs/target/AppWeb_auth_bypass_CVE-2018-8715.js", "wvs/target/OFBiz_SOAPService_deser_rce_CVE-2021-26295.js", "wvs/target/vhost_files_locs_misconfig.js", "wvs/target/cockpit_nosqli_CVE-2020-35847.js", "wvs/target/f5_iControl_REST_RCE_CVE-2021-22986.js", "wvs/target/Cisco_RV_auth_bypass_CVE-2021-1472.js", "wvs/target/web_installer_exposed.js", "wvs/target/ntopng_auth_bypass_CVE-2021-28073.js", "wvs/target/request_smuggling.js", "wvs/target/Hashicorp_Consul_exposed.js", "wvs/target/django_debug_toolbar.js", "wvs/target/VMware_vRealize_SSRF_CVE-2021-21975.js", "wvs/target/GravCMS_unauth_RCE_CVE-2021-21425.js", "wvs/target/caddy_unprotected_api.js", "wvs/target/dragonfly_arbitrary_file_read_CVE-2021-33564.js", "wvs/target/bitrix_audit.js", "wvs/target/nacos_auth_bypass_CVE-2021-29441.js", "wvs/target/sap_bo_bip_ssrf_CVE-2020-6308.js", "wvs/target/detect_apache_shiro_server.js", "wvs/target/jetty_concat_inf_disc_CVE-2021-28164.js", "wvs/target/RethinkDB_open.js", "wvs/target/spring_boot_actuator_logview_path_trav_CVE-2021-21234.js", "wvs/target/open_webpagetest.js", "wvs/target/buddypress_rest_api_privesc_CVE-2021-21389.js", "wvs/target/Hasura_GraphQL_SSRF.js", "wvs/target/grandnode_path_traversal_CVE-2019-12276.js", "wvs/target/SearchBlox_File_Inclusion_CVE-2020-35580.js", "wvs/target/Zimbra_SSRF_CVE-2020-7796.js", "wvs/target/jetty_inf_disc_CVE-2021-34429.js", "wvs/target/Cisco_ASA_XSS_CVE-2020-3580.js", "wvs/target/haproxy_unprotected_api.js", "wvs/target/kong_unprotected_api.js", "wvs/target/OData_feed_accessible_anonymously.js", "wvs/target/Confluence_OGNL_Injection_CVE-2021-26084.js", "wvs/target/microsoft_exchange_preauth_path_confusion_CVE-2021-34473.js", "wvs/target/Atlassian_Jira_File_Read_CVE-2021-26086.js", "wvs/target/ManageEngine_ADSelfService_Plus_auth_bypass_CVE-2021-40539.js", "wvs/target/Django_Debug_Mode.js", "wvs/target/Payara_Micro_File_Read_CVE-2021-41381.js", "wvs/target/keycloak_request_uri_SSRF_CVE-2020-10770.js", "wvs/target/apache_mod_proxy_SSRF_CVE-2021-40438.js", "wvs/target/apache_insecure_path_norm_CVE-2021-41773_CVE-2021-42013.js", "wvs/target/gitlab_exiftool_rce_CVE-2021-22205.js", "wvs/target/http2/http2_pseudo_header_ssrf.js", "wvs/target/Sitecore_XP_RCE_CVE-2021-42237.js", "wvs/target/http2/http2_misrouting_ssrf.js", "wvs/target/http2/http2_web_cache_poisoning.js", "wvs/target/http2/http2_web_cache_poisoning_dos.js", "wvs/target/Apache_Log4j_RCE_404.js", "wvs/httpdata/AjaxControlToolkit_Audit.js", "wvs/httpdata/cache-vary.js", "wvs/httpdata/spring_jsonp_enabled.js", "wvs/httpdata/spring_web_flow_rce.js", "wvs/httpdata/telerik_web_ui_cryptographic_weakness.js", "wvs/httpdata/analyze_parameter_values.js", "wvs/httpdata/apache_struts_rce_S2-057.js", "wvs/httpdata/cors_acao.js", "wvs/httpdata/yii2_debug.js", "wvs/httpdata/CSP_not_implemented.js", "wvs/httpdata/adobe_experience_manager.js", "wvs/httpdata/httpoxy.js", "wvs/httpdata/firebase_db_dev_mode.js", "wvs/httpdata/blazeds_amf_deserialization.js", "wvs/httpdata/text_search.js", "wvs/httpdata/rails_accept_file_content_disclosure.js", "wvs/httpdata/atlassian-crowd-CVE-2019-11580.js", "wvs/httpdata/opensearch-httpdata.js", "wvs/httpdata/csp_report_uri.js", "wvs/httpdata/BigIP_iRule_Tcl_code_injection.js", "wvs/httpdata/password_cleartext_storage.js", "wvs/httpdata/web_applications_default_credentials.js", "wvs/httpdata/HSTS_not_implemented.js", "wvs/httpdata/laravel_audit.js", "wvs/httpdata/whoops_debug.js", "wvs/httpdata/html_auth_weak_creds.js", "wvs/httpdata/clockwork_debug.js", "wvs/httpdata/php_debug_bar.js", "wvs/httpdata/php_console_addon.js", "wvs/httpdata/tracy_debugging_tool.js", "wvs/httpdata/IIS_path_disclosure.js", "wvs/httpdata/missing_parameters.js", "wvs/httpdata/broken_link_hijacking.js", "wvs/httpdata/symfony_audit.js", "wvs/httpdata/jira_servicedesk_misconfiguration.js", "wvs/httpdata/iframe_sandbox.js", "wvs/httpdata/search_paths_in_headers.js", "wvs/httpdata/envoy_metadata_disclosure.js", "wvs/httpdata/insecure_referrer_policy.js", "wvs/httpdata/web_cache_poisoning_via_host.js", "wvs/httpdata/sourcemap_detection.js", "wvs/httpdata/parse_hateoas.js", "wvs/httpdata/typo3_debug.js", "wvs/httpdata/header_reflected_in_cached_response.js", "wvs/httpdata/X_Frame_Options_not_implemented.js", "wvs/httpdata/405_method_not_allowed.js", "wvs/httpdata/javascript_library_audit_external.js", "wvs/httpdata/http_splitting_cloud_storage.js", "wvs/httpdata/apache_shiro_auth_bypass_CVE-2020-17523.js", "wvs/httpdata/acusensor-packages.js", "wvs/httpdata/joomla_debug_console.js", "wvs/httpdata/mitreid_connect_ssrf_CVE-2021-26715.js", "wvs/httpdata/saml_endpoint_audit.js", "wvs/httpdata/sca_analyze_package_files.js", "wvs/httpdata/pyramid_debugtoolbar.js", "wvs/httpdata/adminer_ssrf_CVE-2021-21311.js", "wvs/httpdata/Tapestry_audit.js", "wvs/target/web_cache_poisoning.js", "wvs/target/php_xdebug_rce.js", "wvs/input_group/json/expressjs_layout_lfr_json.js", "wvs/input_group/query/expressjs_layout_lfr_query.js", "wvs/input_group/query/prototype_pollution_query.js", "ovas/"},
	}

	postDataJSON, err := json.Marshal(postData)
	if err != nil {
		fmt.Println("JSON 编码失败:", err)
		return ""
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", getTargetURL, bytes.NewBuffer(postDataJSON))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 获取配置信息
	getTargetURL = awvsURL + "/api/v1/scanning_profiles"

	// 创建 HTTP 请求
	req, err = http.NewRequest("GET", getTargetURL, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client = &http.Client{Transport: ssl}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 读取响应内容
	var responseJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseJSON); err != nil {
		fmt.Println("JSON 解码失败:", err)
		return ""
	}

	// 检查是否包含 "Apache Log4j RCE" 的扫描配置
	for _, profile := range responseJSON["scanning_profiles"].([]interface{}) {

		profileMap := profile.(map[string]interface{})

		if profileMap["name"].(string) == "Bug Bounty" {
			profileID := profileMap["profile_id"].(string)
			return profileID
		}
	}

	fmt.Println("未找到 Bug Bounty 的扫描配置")
	return ""
}

func custom_cves() string {
	getTargetURL := awvsURL + "/api/v1/scanning_profiles"

	// 构造 POST 请求的数据
	postData := map[string]interface{}{
		"name":   "cves",
		"custom": true,
		"checks": []string{"wvs/Crawler", "wvs/deepscan", "wvs/custom-scripts", "wvs/MalwareScanner", "wvs/Scripts/PerFile", "wvs/Scripts/PerFolder", "wvs/Scripts/PerScheme", "wvs/Scripts/PerServer/AJP_Audit.script", "wvs/Scripts/PerServer/ASP_NET_Error_Message.script", "wvs/Scripts/PerServer/ASP_NET_Forms_Authentication_Bypass.script", "wvs/Scripts/PerServer/Apache_Axis2_Audit.script", "wvs/Scripts/PerServer/Apache_Geronimo_Default_Administrative_Credentials.script", "wvs/Scripts/PerServer/Apache_Proxy_CONNECT_Enabled.script", "wvs/Scripts/PerServer/Apache_Roller_Audit.script", "wvs/Scripts/PerServer/Apache_Running_As_Proxy.script", "wvs/Scripts/PerServer/Apache_Server_Information.script", "wvs/Scripts/PerServer/Apache_Solr_Exposed.script", "wvs/Scripts/PerServer/Apache_Unfiltered_Expect_Header_Injection.script", "wvs/Scripts/PerServer/Apache_XSS_via_Malformed_Method.script", "wvs/Scripts/PerServer/Apache_httpOnly_Cookie_Disclosure.script", "wvs/Scripts/PerServer/Apache_mod_negotiation_Filename_Bruteforcing.script", "wvs/Scripts/PerServer/Arbitrary_file_existence_disclosure_in_Action_Pack.script", "wvs/Scripts/PerServer/Barracuda_locale_Directory_Traversal.script", "wvs/Scripts/PerServer/Bash_RCE_Server_Audit.script", "wvs/Scripts/PerServer/CRLF_Injection_PerServer.script", "wvs/Scripts/PerServer/ColdFusion_Audit.script", "wvs/Scripts/PerServer/ColdFusion_User_Agent_XSS.script", "wvs/Scripts/PerServer/ColdFusion_v8_File_Upload.script", "wvs/Scripts/PerServer/ColdFusion_v9_Solr_Exposed.script", "wvs/Scripts/PerServer/CoreDumpCheck.script", "wvs/Scripts/PerServer/Database_Backup.script", "wvs/Scripts/PerServer/Django_Admin_Weak_Password.script", "wvs/Scripts/PerServer/Error_Page_Path_Disclosure.script", "wvs/Scripts/PerServer/Flask_Debug_Mode.script", "wvs/Scripts/PerServer/Frontpage_Extensions_Enabled.script", "wvs/Scripts/PerServer/Frontpage_Information.script", "wvs/Scripts/PerServer/Frontpage_authors_pwd.script", "wvs/Scripts/PerServer/GlassFish_41_Directory_Traversal.script", "wvs/Scripts/PerServer/GlassFish_Audit.script", "wvs/Scripts/PerServer/Hadoop_Cluster_Web_Interface.script", "wvs/Scripts/PerServer/Horde_IMP_Webmail_Exploit.script", "wvs/Scripts/PerServer/IBM_WCM_XPath_Injection.script", "wvs/Scripts/PerServer/IBM_WebSphere_Audit.script", "wvs/Scripts/PerServer/IIS_Global_Asa.script", "wvs/Scripts/PerServer/IIS_Internal_IP_Address.script", "wvs/Scripts/PerServer/IIS_Unicode_Directory_Traversal.script", "wvs/Scripts/PerServer/IIS_service_cnf.script", "wvs/Scripts/PerServer/IIS_v5_NTML_Basic_Auth_Bypass.script", "wvs/Scripts/PerServer/Ioncube_Loader_Wizard.script", "wvs/Scripts/PerServer/JBoss_Audit.script", "wvs/Scripts/PerServer/JBoss_Status_Servlet_Information_Leak.script", "wvs/Scripts/PerServer/JBoss_Web_Service_Console.script", "wvs/Scripts/PerServer/JMX_RMI_service.script", "wvs/Scripts/PerServer/Java_Application_Servers_Fuzz.script", "wvs/Scripts/PerServer/Java_Debug_Wire_Protocol_Audit.script", "wvs/Scripts/PerServer/Jetty_Audit.script", "wvs/Scripts/PerServer/Lotus_Domino_crlf_xss.script", "wvs/Scripts/PerServer/Misfortune_Cookie.script", "wvs/Scripts/PerServer/MongoDB_Audit.script", "wvs/Scripts/PerServer/Movable_Type_4_RCE.script", "wvs/Scripts/PerServer/Nginx_PHP_FastCGI_Code_Execution_File_Upload.script", "wvs/Scripts/PerServer/Oracle_Application_Logs.script", "wvs/Scripts/PerServer/Oracle_Reports_Audit.script", "wvs/Scripts/PerServer/PHP_CGI_RCE_Force_Redirect.script", "wvs/Scripts/PerServer/PHP_Hash_Collision_Denial_Of_Service.script", "wvs/Scripts/PerServer/Parallels_Plesk_Audit.script", "wvs/Scripts/PerServer/Plesk_Agent_SQL_Injection.script", "wvs/Scripts/PerServer/Plesk_SSO_XXE.script", "wvs/Scripts/PerServer/Plone&Zope_Remote_Command_Execution.script", "wvs/Scripts/PerServer/Pyramid_Debug_Mode.script", "wvs/Scripts/PerServer/Railo_Audit.script", "wvs/Scripts/PerServer/Registration_Page.script", "wvs/Scripts/PerServer/Reverse_Proxy_Bypass.script", "wvs/Scripts/PerServer/RubyOnRails_Database_File.script", "wvs/Scripts/PerServer/SSL_Audit.script", "wvs/Scripts/PerServer/Same_Site_Scripting.script", "wvs/Scripts/PerServer/Snoop_Servlet.script", "wvs/Scripts/PerServer/Spring_Boot_Actuator.script", "wvs/Scripts/PerServer/Subdomain_Takeover.script", "wvs/Scripts/PerServer/Tomcat_Audit.script", "wvs/Scripts/PerServer/Tomcat_Default_Credentials.script", "wvs/Scripts/PerServer/Tomcat_Examples.script", "wvs/Scripts/PerServer/Tomcat_Hello_JSP_XSS.script", "wvs/Scripts/PerServer/Tomcat_Status_Page.script", "wvs/Scripts/PerServer/Tornado_Debug_Mode.script", "wvs/Scripts/PerServer/Track_Trace_Server_Methods.script", "wvs/Scripts/PerServer/Unprotected_phpMyAdmin_Interface.script", "wvs/Scripts/PerServer/VMWare_Directory_Traversal.script", "wvs/Scripts/PerServer/VirtualHost_Audit.script", "wvs/Scripts/PerServer/WAF_Detection.script", "wvs/Scripts/PerServer/WEBrick_Directory_Traversal.script", "wvs/Scripts/PerServer/WebInfWebXML_Audit.script", "wvs/Scripts/PerServer/WebLogic_Audit.script", "wvs/Scripts/PerServer/Web_Server_Default_Welcome_Page.script", "wvs/Scripts/PerServer/Web_Statistics.script", "wvs/Scripts/PerServer/XML_External_Entity_Injection_Server.script", "wvs/Scripts/PerServer/Zend_Framework_Config_File.script", "wvs/Scripts/PerServer/elasticsearch_Audit.script", "wvs/Scripts/PerServer/elmah_Information_Disclosure.script", "wvs/Scripts/PerServer/lighttpd_v1434_Sql_Injection.script", "wvs/Scripts/PerServer/ms12-050.script", "wvs/Scripts/PerServer/phpMoAdmin_Remote_Code_Execution.script", "wvs/Scripts/PerServer/Weblogic_wls-wsat_RCE.script", "wvs/Scripts/PerServer/Atlassian_OAuth_Plugin_IconUriServlet_SSRF.script", "wvs/Scripts/PerServer/PHP_FPM_Status_Page.script", "wvs/Scripts/PerServer/Test_CGI_Script.script", "wvs/Scripts/PerServer/Cisco_ASA_Path_Traversal_CVE-2018-0296.script", "wvs/Scripts/PerServer/Liferay_RCE_tra-2017-01.script", "wvs/Scripts/PerServer/Liferay_Xmlrpc_SSRF.script", "wvs/Scripts/PerServer/Spring_RCE_CVE-2016-4977.script", "wvs/Scripts/PostScan", "wvs/input_group/query/prototype_pollution_query.js", "wvs/input_group/json/expressjs_layout_lfr_json.js", "wvs/input_group/query/expressjs_layout_lfr_query.js", "ovas/"},
	}

	postDataJSON, err := json.Marshal(postData)
	if err != nil {
		fmt.Println("JSON 编码失败:", err)
		return ""
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", getTargetURL, bytes.NewBuffer(postDataJSON))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client := &http.Client{Transport: ssl}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 获取配置信息
	getTargetURL = awvsURL + "/api/v1/scanning_profiles"

	// 创建 HTTP 请求
	req, err = http.NewRequest("GET", getTargetURL, nil)
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return ""
	}

	// 设置请求头
	req.Header = headers

	// 发送 HTTP 请求
	client = &http.Client{Transport: ssl}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("发送 POST 请求失败:", err)
		return ""
	}
	defer resp.Body.Close()

	// 读取响应内容
	var responseJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseJSON); err != nil {
		fmt.Println("JSON 解码失败:", err)
		return ""
	}

	// 检查是否包含 "Apache Log4j RCE" 的扫描配置
	for _, profile := range responseJSON["scanning_profiles"].([]interface{}) {

		profileMap := profile.(map[string]interface{})

		if profileMap["name"].(string) == "cves" {
			profileID := profileMap["profile_id"].(string)
			return profileID
		}
	}

	fmt.Println("未找到 cves 的扫描配置")
	return ""
}
