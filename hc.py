from mode.mulu import mulu
from mode.cunhuo import ping_all
import sys
import getopt
import sys


def help():
    '''
    帮助展示页面
    '''
    print("-----------------------------------hc------------------------------------------")
    print("|                    _     _                                                  |")
    print("|                   | |   | |  ___      ___   ___  __ _  _ __                 |")
    print("|                   | |---| | / __|    / __| / __|/ _` || '_ \                |")
    print("|                   | |---| || (__     \__ \| (__| (_| || | | |               |")
    print("|                   |_|   |_| \___|    |___/ \___|\__,_||_| |_|               |")
    print("|                                                                             |")
    print("|++++++++++++++++++++++++++++++++使用说明+++++++++++++++++++++++++++++++++++++|")
    print("|    参数                                                                     |")
    print("|        -h --help                     - 输出帮助界面                         |")
    print("|        -i --ip                       - 设定目标IP 需要参数                  |")
    print("|                                        例如 10.10.10.10或10.10.10.10/24     |")
    print("|        -u --url                      - 设定目标url                          |")
    print("|        -t --thread                   - 设定使用的线程                       |")
    print("|        -d --dictionary               - 设定使用的字典目录                   |")
    print("|    功能                                                                     |")
    print("|        -A --Alive                    - 使用Ping来探测主机是否存活          |")
    print("|        -L --List                     - 扫描网站后台                         |")
    print("-----------------------------------end-----------------------------------------")

def main():
    '''
    主函数，负责读取用户的参数，并调用应有的功能模块
    '''
    ip_net = ""         # 存放IP
    url = ""            # 存放URL
    thread = 0          # 设置线程
    CH = False          # 是否进行存货扫描
    ML = False          # 是否进行目录扫描
    txt = ""            # 字典的存放目录

    # 读取命令行选项,若没有该选项则显示用法
    if not len(sys.argv[1:]):
        help()
    
    # 读取用户输入的参数
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:u:d:t:AL",["help","ip=","url=","thread=","dictionary=","Alive","List"])
    except getopt.GetoptError as err:
        print(str(err))
        help()

    # 从opts中读取数据，o为参数,a为参数后带的值
    for o,a in opts:
        if o in ("-h","--help"):            # 如果参数为help，展示help界面
            help()
        elif o in ("-i","--ip"):            # 如果参数为ip，将用户输入的ip赋值给ip_net
            ip_net = a 
        elif o in ("-A","--Alive"):          # 如果参数为P，开启ping功能的主机存活扫描功能
            CH = True
        elif o in ("-t","--thread"):        # 如果参数为t，则将用户设置的线程数量赋值给thread
            thread = a
        elif o in ("-u","--url"):           # 如果参数为url，将用户输入的url赋值给url
            url = a
        elif o in ("-L","--List"):          # 如果参数为list，则开启目录扫描功能
            ML = True
        elif o in ("-d","--dictionary"):    # 如果参数为dictionary，则将用户输入的目录赋值给txt
            txt = a

    # 判断用户想启用什么功能，并调用对应函数
    if len(ip_net) and CH == True:          # 开启Ping主机存活功能扫描
        ping_all(ip_net)
    elif len(url) and ML == True:           # 使用目录扫描
        if thread == 0 :
            thread = 10000                  # 用户未设置线程则默认为 10000
        if txt == "" :
            txt = "../mulu.txt"             # 用户未设置字典则使用默认字典
        mulu(url,thread,txt)


main()