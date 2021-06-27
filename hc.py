import mode.loudong
import mode.mulu
import mode.cunhuo
import mode.duankou
import sys
import getopt
import time

def head():
    print("")
    print("      ++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("      |       _     _                                        |")
    print("      |      | |   | |  ___      ___   ___  __ _  _ __       |")
    print("      |      | |---| | / __|    / __| / __|/ _` || '_ \      |")
    print("      |      | |---| || (__     \__ \| (__| (_| || | | |     |")
    print("      |      |_|   |_| \___|    |___/ \___|\__,_||_| |_|     |")
    print("      |                                                      |")
    print("      ++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("")

def help():
    '''
    帮助展示页面
    '''
    print("")
    print("                          【使用说明】")
    print("    【参数】")
    print("        -h --help                     - 输出帮助界面")
    print("        -i --ip                       - 设定目标IP 需要参数")
    print("                                        例如 10.10.10.10或10.10.10.10/24")
    print("        -u --url                      - 设定目标url")
    print("        -t --thread                   - 设定使用的线程")
    print("        -d --dictionary               - 设定使用的字典目录")
    print("        -p --port                     - 指定扫描的端口，用“,”隔开。提供了3种扫描方式，默认为常用端口")
    print("                all_port              - 设定端口扫描为全端口扫描")
    print("                simple_port           - 设定端口扫描为简单端口扫描")
    print("                often_port            - 设置端口扫描为常用端口扫描")
    print("    【功能】")
    print("        -A --Alive                    - 使用Ping来探测主机是否存活")
    print("        -L --List                     - 扫描网站后台")
    print("        -P --Port                     - 扫描网站端口，可以用-p来进行指定，不指定默认为常用端口")
    print("        -H --Hole                     - 扫描网站漏洞")
    print("        -U --Utilize                  - 对网站漏洞利用")
    print("        -S --Shell                    - 配套脚本接收shell用")
    print("           --AUTO                     - 根据输入的IP自动进行所有功能的监测")
    print("")

def main():
    '''
    主函数，负责读取用户的参数，并调用应有的功能模块
    '''
    ip_net = ""         # 存放IP
    url = ""            # 存放URL
    thread = 0          # 设置线程
    CH = False          # 是否进行存活扫描
    ML = False          # 是否进行目录扫描
    txt = ""            # 字典的存放目录
    PORT = False        # 是否进行端口扫描
    use_port = ''       # 使用的端口
    Hole = False        # 是否进行漏洞扫描
    auto = 0            # 是否开启自动利用漏洞

    # 读取命令行选项,若没有该选项则显示用法
    if not len(sys.argv[1:]):
        head()
        help()
    
    # 读取用户输入的参数
    try:
        opts, args = getopt.getopt(sys.argv[1:], 
        "hi:u:d:t:p:PALH",
        ["help","ip=","url=","thread=","dictionary=","Alive","List","port=","Port","all_port","simple_port",
        "often_port","Hole","AUTO"])
    except getopt.GetoptError as err:
        print(str(err))
        head()
        help()

    # 从opts中读取数据，o为参数,a为参数后带的值
    for o,a in opts:
        if o in ("-h","--help"):              # 如果参数为help，展示help界面
            head()
            help()
        elif o in ("-i","--ip"):              # 如果参数为ip，将用户输入的ip赋值给ip_net
            ip_net = a    
        elif o in ("-A","--Alive"):           # 如果参数为P，开启ping功能的主机存活扫描功能
            CH = True
        elif o in ("-t","--thread"):          # 如果参数为t，则将用户设置的线程数量赋值给thread
            thread = int(a)
        elif o in ("-u","--url"):             # 如果参数为url，将用户输入的url赋值给url
            url = a
        elif o in ("-L","--List"):            # 如果参数为list，则开启目录扫描功能
            ML = True
        elif o in ("-d","--dictionary"):      # 如果参数为dictionary，则将用户输入的目录赋值给txt
            txt = a
        elif o in ("-p","--port"):            # 如果参数为p，则用户设置使用的端口
            use_port = a
        elif o in ("-P","--Port"):            # 如果参数为P，则用户想进行端口扫描
            PORT = True 
        elif o in ("-H","--Hole"):            # 如果参数为H，则用户想进行漏洞扫描
            Hole = True
        elif o in ("--AUTO"):                 # 如果参数为AUTO,则对扫描到的漏洞自动进行利用 
            auto = 1
    
    if thread == 0 :
        thread = 100                    # 用户未设置线程则默认为 100
    if txt == "" :
        txt = "../mulu.txt"             # 用户未设置字典则使用默认字典
    if len(use_port) == 0:
        use_port = 'often_port'

    
    # 判断用户想启用什么功能，并调用对应函数
    if len(ip_net) and CH == True:          # 开启Ping主机存活功能扫描
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 开始")
        head()
        mode.cunhuo.ping_all(ip_net)
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 结束")
    if len(url) and ML == True:             # 使用目录扫描
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 开始")
        head()
        mode.mulu.mulu_scan(url,thread,txt)
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 结束")
    if PORT == True:
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 开始")
        head()
        mode.duankou.port_scan(ip_net,use_port,thread,3)
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 结束")
    if Hole == True:
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 开始")
        head()
        mode.loudong.loudong_scan(url,auto)
        print(time.strftime("\n%Y-%m-%d %H:%M:%S", time.localtime())+" 结束")



main()