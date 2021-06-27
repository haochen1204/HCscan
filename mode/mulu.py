import os
import queue
from urllib.parse import urlparse
import requests
import time
import threading

q=queue.Queue()
end_num = 0
start_num = 0
list_num = 0
alive_num = 0

headers = {
    'Host':'',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate'
}

def scan(url):
    '''
    目录扫描的函数
    '''
    global end_num
    global list_num
    global alive_num
    global headers
    res=urlparse(url) 
    headers['Host']=res.netloc
    while not q.empty():                        # 只要字典里不为空，就一直循环
        list_num+=1
        dir=q.get()                             # 把存储的payload取出来
        urls=url+dir                            # url+payload就是一个payload
        urls=urls.replace('\n','')              # 利用回车来分割开来，不然打印的时候不显示
        code=requests.get(urls,headers)                 # 把拼接的url发起http请求
        if code.status_code==200 or code.status_code==403:              # 如果返回包状态码为200或者403，就打印url+状态码
            print('[+] '+urls+'           <'+str(code.status_code)+'>')
            alive_num+=1
        else:                                   # 不然就打印url+状态码，并延时一秒
            # print('[-] '+urls+'       <'+str(code.status_code)+'>')
            time.sleep(1)  
    end_num+=1
 
def mulu_scan(url,thread,txt):
    '''
    读取字典与开启多线程的函数
    '''
    global end_num
    global start_num
    global list_num
    global alive_num

    # 获取当前的路径
    path=os.path.dirname(os.path.realpath(__file__))     

    # 当前路径加上字典名就是绝对路径，然后循环字典里的payload
    for dir in open(path+"/"+txt):
            q.put(dir)

    # 使用多线程进行扫描，线程数量取决与传入的thread
    for i in range(int(thread)):
        t = threading.Thread(target=scan,args=(url,))
        t.start()
        start_num+=1

    # 循环等待所有线程执行完毕，打印执行结果 
    while(True):
        if start_num == end_num :
            print("共扫描 ",list_num," 个目录")
            print("发现存在 ",alive_num," 个目录")
            print("[GG]感谢使用HCscan！")
            break
