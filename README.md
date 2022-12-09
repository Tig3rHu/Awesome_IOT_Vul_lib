# MessageForV
This is a repository for collecting and collating vulnerability disclosures, tips, and tools


# Vulnerability Disclosures

## router
[1] https://wzt.ac.cn/2021/01/13/AC2400_vuln/

Summary: Analyze an unauthorized access vulnerability

[2] https://github.com/aaronsvk/CVE-2022-30075

Summary:  TP-Link AX50 RCE

[3] https://blog.coffinsec.com//research/2022/07/02/orbi-nday-exploit-cve-2020-27861.html

Summary: NetGear orbi RCE

[4] https://blog.leakix.net/2022/06/d-link-dir-842-rev-b-privilege-escalation/
   
   https://eh-easyhacks.blogspot.com/2022/04/cve-2021-45382.html
   
Summary: 介绍DIR-842 设备开启sharePort 功能，然后 /ddns_check.ccp 获取命令执行

[5] https://blog.viettelcybersecurity.com/1day-to-0day-on-tl-link-tl-wr841n/

Summary: 这个文章里讲了TL-Link WR841N 的漏洞，分析了1day 的触发原因，然后挖到了0day， 0day 的漏洞原理:循环给一个局部变量增加字节，没有显示字节的大小，导致栈溢出（区别于strcpy 这种方式）; 还讲述了栈溢出的漏洞exploit。

[6] https://blog.viettelcybersecurity.com/tp-link-tl-wr940n-httpd-httprpmfs-stack-based-buffer-overflow-remote-code-execution-vulnerability/

Summary : TP-Link TL-WR940N：1day（CVE-2022-24355）缓冲区溢出RCE漏洞分析

[7] https://boschko.ca/tenda_ac1200_router/   https://boschko.ca/glinet-router/   https://boschko.ca/hardware_hacking_yo_male_fertility/

Summary : The author's analysis is more detailed, the thinking process is worth learning 

[8]https://boschko.ca/tenda_ac1200_router/

Summary: Tenda AC1200 漏洞报告

[9] https://github.com/b1ack0wl/vulnerability-write-ups/blob/master/TP-Link/WR940N/112022/Part1.md

TP-Link WR940N SSDP 漏洞

## Camera

[1] https://talosintelligence.com/vulnerability_reports/TALOS-2021-1424

Summary:  Reolink RLC-410W v3.0.0.136_20121102  ,There are multiple vulnerabilities，including ‘factory’ binary firmware update vulnerabilty， information disclosure, denial of service vulnerability, authentication bypass
![image](https://github.com/Tig3rHu/MessageForV/blob/main/MarkdownImage/4c845ba2a64d47679ce275eb410359d.png)

[2] https://palmopensource.com/hardware/jw0004-webcam.php

Summary: Wanscam JW0004 IP Webcam hacking, this article describe some idea that about upnpd and authentication vulnerability

[3] https://www.pentestpartners.com/security-blog/hacking-the-ip-camera-part-1/

summary : The firmware to decrypt use unzip tool that we can use unzip and string to find the key,

[4] https://github.com/full-disclosure/FDEU-CVE-2021-525A

summary : D-Link credentials decryption tool poc

[5] https://www.exploitee.rs/index.php/

summary : A platform to disclose some vulnerabilities

[6] http://www.hydrogen18.com/blog/hacking-zyxel-ip-cameras-pt-1.html

summary : Hack the Zyxel IP camera to obtain the root shell

[7] https://vulncheck.com/blog/xiongmai-iot-exploitation

summary : Some research on historical vulnerabilities of Xiongmai devices

## Security of Car
海盗讲车：黑掉T-Box
https://www.freebuf.com/articles/endpoint/240414.html?ref=www.ctfiot.com

对挪威一款Zaptec Pro 电动车充电桩的安全研究报告
https://www.mnemonic.io/resources/blog/reverse-engineering-an-ev-charger/

海盗讲车：车机的渗透思路与实例分析
https://www.freebuf.com/articles/endpoint/241930.html?ref=www.ctfiot.com



## Firewall

# Idea

## Automation Vulnerability discover
[1] use Binary Ninja to discover vulnerabilty of IOT device

https://dawnslab.jd.com/binaryninja1-zh-cn/

[2]Finding Vulnerabilities with VulFi IDA Plugin

https://www.accenture.com/us-en/blogs/security/finding-vulnerabilities-vulfi-ida-plugin

