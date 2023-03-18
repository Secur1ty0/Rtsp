## Rtsp-scan

多线程并发rtsp协议端口扫描工具

## Usage

```bash
rtsp_scan [-f <filename>|-i <ip address or CIDR>] -p <port(s)> [-o <output file path>] [-t <threads>]
  -f string
    	file with list of IP addresses to scan (required)
  -i string
    	IP address or CIDR notation of network to scan (-i and -f are mutually exclusive)
  -p string
    	port(s) to scan (required) (default "554")
  -t int
    	number of threads (default 1)
```

## Todo

- uri识别
- 爆破