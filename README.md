# HCscan

![Snipaste_2021-06-19_10-59-57](https://github.com/haochen1204/HCscan/blob/master/picture/help.png)

学校大作业，具有端口扫描、存活扫描、目录爆破、简单的漏送扫描并利用的功能，可以设置线程、延时等。具体可以输入-h查看。

存活扫描，采用icmp协议，通过Ping来判断，至少需要-A -i 192.168.0.0/16 2个参数 1个输入

端口扫描，采用tcp协议，可以进行全端口扫描、常用端口扫描和简单端口扫描，至少需要-P -i 2个参数，可使用-p 指定使用的端口（simple_port all_port often_port）

目录扫描，至少需要-L -u 2个参数 -u后需要加入url 建议加入-E 在扫描结束后通过生成的excel查看扫描结果

漏洞扫描，加入了12个漏洞，可以进行扫描和利用，至少需要-H -u 2个参数，加--AUTO参数可以进行自动化利用

其他请输入-h查看帮助文档

需要xlwt requests库的支持