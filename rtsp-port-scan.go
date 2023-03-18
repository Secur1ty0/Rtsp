package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 解析端口参数
func parsePorts(portsArg string) []int {
	var ports []int
	portRanges := strings.Split(portsArg, ",")
	for _, pr := range portRanges {
		if strings.Contains(pr, "-") { // 端口范围
			portsRange := strings.Split(pr, "-")
			startPort, _ := strconv.Atoi(portsRange[0])
			endPort, _ := strconv.Atoi(portsRange[1])
			for i := startPort; i <= endPort; i++ {
				ports = append(ports, i)
			}
		} else { // 单个端口
			port, _ := strconv.Atoi(pr)
			ports = append(ports, port)
		}
	}
	return ports
}

func readIPsFromFile(ipFile string) []string {
	// 读取IP地址列表文件
	ipFileHandle, err := os.Open(ipFile)
	if err != nil {
		fmt.Println("Failed to open IP address file:", err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(ipFileHandle)
	var ips []string
	for scanner.Scan() {
		ip0 := scanner.Text()
		ips = append(ips, ip0)
	}
	return ips
}
func ParseIPv4Network(networkStr string) ([]string, error) {
	parts := strings.Split(networkStr, "/")

	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid IPv4 network string: %s", networkStr)
	}

	baseIP := parts[0]
	subnetMaskLen, err := strconv.Atoi(parts[1])

	if err != nil || subnetMaskLen < 0 || subnetMaskLen > 32 {
		return nil, fmt.Errorf("Invalid IPv4 subnet mask: %s", parts[1])
	}

	subnetMask := net.CIDRMask(subnetMaskLen, 32)
	ip := net.ParseIP(baseIP).To4()

	if ip == nil {
		return nil, fmt.Errorf("Invalid IPv4 address: %s", baseIP)
	}

	networkIP := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		networkIP[i] = ip[i] & subnetMask[i]
	}

	numHosts := int(math.Pow(2, float64(32-subnetMaskLen)) - 2)
	ips := make([]string, numHosts)

	for i := 1; i <= numHosts; i++ {
		hostIP := make(net.IP, len(ip))
		copy(hostIP, networkIP)
		binary.BigEndian.PutUint32(hostIP.To4(), binary.BigEndian.Uint32(hostIP.To4())+uint32(i))
		ips[i-1] = hostIP.String()
	}

	return ips, nil
}

func main() {
	// 解析命令行参数
	var threads int
	var ipFile, portArg, ipAddr, outputFile string
	outputFile = "rtsp-result.txt"
	flag.IntVar(&threads, "t", 1, "number of threads")
	flag.StringVar(&ipFile, "f", "", "file with list of IP addresses to scan (required)")
	flag.StringVar(&ipAddr, "i", "", "IP address or CIDR notation of network to scan (-i and -f are mutually exclusive)")
	flag.StringVar(&portArg, "p", "554", "port(s) to scan (required)")
	//flag.StringVar(&outputFile, "o", "", "output file path (optional)")
	flag.Parse()

	// 检查必填参数
	if ipFile == "" && ipAddr == "" || portArg == "" {
		fmt.Println("Usage: rtsp-port-scan [-f <filename>|-i <ip address or CIDR>] -p <port(s)> [-o <output file path>] [-t <threads>]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 解析端口参数
	ports := parsePorts(portArg)
	// 解析IP地址列表
	var ips []string

	if strings.Contains(ipAddr, "/") {
		ips, _ = ParseIPv4Network(ipAddr)
	} else if ip := net.ParseIP(ipAddr); ip != nil {
		ips = []string{ip.String()}
	} else {
		ips = readIPsFromFile(ipAddr)
	}

	resultChan := make(chan string, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			resultChan <- fmt.Sprintf("%s:%d", ip, port)
		}
	}
	close(resultChan)

	wg := sync.WaitGroup{}
	resultMutex := sync.Mutex{}
	var result []string

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range resultChan {
				fmt.Printf("Scanning IP address %v...\n", target)
				conn, err := net.DialTimeout("tcp", target, time.Duration(500*time.Millisecond))
				if err != nil {
					continue
				}
				reqdata := fmt.Sprintf("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: LibVLC/3.0.18 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n", target)
				_, err = conn.Write([]byte(reqdata))
				if err != nil {
					conn.Close()
					continue
				}

				var buf [1024]byte
				n, err := conn.Read(buf[:])
				if err != nil {
					conn.Close()
					continue
				}

				response := string(buf[:n])
				//fmt.Println("resp ", response)
				if strings.Contains(response, "RTSP/") && strings.Contains(response, "CSeq:") && strings.Contains(response, "Public:") {
					fmt.Printf("[+] %s RTSP protocol is enabled\n", target)
					resultMutex.Lock()
					result = append(result, target)
					resultMutex.Unlock()
				}

				conn.Close()
			}
		}()
	}

	wg.Wait()

	if outputFile != "" {
		// 将结果写入输出文件
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Println("Failed to create output file:", err)
			os.Exit(1)
		}
		defer file.Close()
		writer := bufio.NewWriter(file)
		for _, r := range result {
			writer.WriteString(r + "\n")
		}
		writer.Flush()
	} else {
		// 直接输出结果
		for _, r := range result {
			fmt.Println(r)
		}
	}
}
