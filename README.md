# Awesome IOT vulnerability Library
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

[10] https://www.greynoise.io/blog/debugging-d-link-emulating-firmware-and-hacking-hardware

对DIR-864 固件模拟和漏洞挖掘，通过上传配置文件，打开路由器的telnetd。

[11] https://blog.talosintelligence.com/vulnerability-spotlight-netgear-orbi-router-vulnerable-to-arbitrary-command-execution/
Netgear Orbi Satellite RBS750，远程代码执行漏洞 TAOS-2022-1595 (CVE-2022-36429)

[12] https://mahaloz.re/2023/02/25/pwnagent-netgear.html
PwnAgent：带有 CVE-2023-24749 的 Netgear RAX 路由器中的一键式 WAN 端 RCE

[13] https://code-byter.com/2022/04/06/fantec-wifi.html
WiFi Travel Router 漏洞, 文件上传漏洞，栈溢出漏洞利用，有利用过程

[14] https://labs.ioactive.com/2020/09/no-buffers-harmed-rooting-sierra.html
sierra wireless 设备 固件解密方法

[15] https://research.aurainfosec.io/pentest/bee-yond-capacity/
从一个服务中发现了未授权缓冲区溢出的漏洞，到完整的漏洞利用，文件由alsr 的保护，文中讲述了如何对收到alsr 保护进行漏洞利用。

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

[8] https://www.somersetrecon.com/blog/2022/hacking-the-furbo-dog-camera-part-iii

summary : A means of attacking by updating firmware

[9] https://medium.com/@two06/hacking-a-tapo-tc60-camera-e6ce7ca6cad1

summary: 针对摄像头的漏洞挖掘，每个步骤介绍都很详细

## Security of Car
海盗讲车：黑掉T-Box
https://www.freebuf.com/articles/endpoint/240414.html?ref=www.ctfiot.com

对挪威一款Zaptec Pro 电动车充电桩的安全研究报告
https://www.mnemonic.io/resources/blog/reverse-engineering-an-ev-charger/

海盗讲车：车机的渗透思路与实例分析
https://www.freebuf.com/articles/endpoint/241930.html?ref=www.ctfiot.com

## Firewall

## NAS
zyxel NAS d的认证绕过漏洞
https://bugprove.com/knowledge-hub/cve-2023-4473-and-cve-2023-4474-authentication-bypass-and-multiple-blind-os-command-injection-vulnerabilities-in-zyxel-s-nas-326-devices/

# Idea

## Automation Vulnerability discover
[1] use Binary Ninja to discover vulnerabilty of IOT device

https://dawnslab.jd.com/binaryninja1-zh-cn/

[2]Finding Vulnerabilities with VulFi IDA Plugin

https://www.accenture.com/us-en/blogs/security/finding-vulnerabilities-vulfi-ida-plugin

[3] UBI 固件镜像打包
https://blog.csdn.net/sxlworld/article/details/123871505


# encrpty 

[1] https://bishopfox.com/blog/breaking-fortinet-firmware-encryption
fortinet 固件解密
[2] https://cloud.tencent.com/developer/article/1005700
四个字节的安全 ：一次固件加密算法的逆向分析, 对固件进行解密分析，其中有对AES加密和sha加密的分析，以及对芯片中不同内存区中寄存器作用的分析。很干货

[3] Zyxel设备固件解密&提取分析
https://mp.weixin.qq.com/s/7MAYQEbv4KlSnehJLd8GqQ
https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/



# Android Kernel & devices

Rooting the FiiO M6 - Part 1 - Using the "World's Worst Fuzzer" To Find A Kernel Bug
https://stigward.github.io/posts/fiio-m6-kernel-bug/

对android 系统的漏洞挖掘
https://blog.stmcyber.com/pax-pos-cves-2023/

大疆无人机DJI Mini 3 Pro 的固件分析&解密，服务分析，漏洞挖掘
https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-1-firmware-analysis
https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-2-vulnerability-analysis
https://icanhack.nl/blog/dji-rm500-privilege-escalation/
