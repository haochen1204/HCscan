'''
Python局域网扫描获取存活主机IP
1、获取本机操作系统名称
2、获取本机IP地址
3、ping指定IP判断主机是否存活
4、ping所有IP获取所有存活主机
'''
import platform
import copy
import os
import threading
import time
import xlwt
import ipaddress

ip_alives = 0
ip_num = 0
request_list = list()

def ping_ip(ip):                                           
    '''
    使用ping来判断主机是否存活
    '''
    global ip_alives
    global ip_num
    global request_list

    # 执行系统ping命令，并将执行结果存放在output中
    output = os.popen('ping  %s'%ip).readlines()

    # 从output中循环读取数据
    for w in output:
        # 判断每行中是否存在TTL，存在则说明ping通，主机存活
        if str(w).upper().find('TTL')>=0:
            ip_alives+=1
            print("[+]",ip,"is alive")
            request_list.append(str(ip))
            break
    ip_num+=1
    
def write_in(net):
    global request_list
    work_Book=xlwt.Workbook(encoding='utf-8')
    sheet=work_Book.add_sheet('主机扫描')
    sheet.write(0,0,'存活主机：')
    result_lists=copy.deepcopy(request_list)
    result_lists.reverse()
    i=1 
    while len(result_lists)!=0:
        msg=result_lists.pop()
        sheet.write(i,0,msg)
        i+=1
    name = str(net) + '存活扫描.xls'
    work_Book.save(name)

def ping_all(network):                            
    '''
    从IP来获取所有主机
    '''
    global ip_alives
    global ip_num
    num = 0
    # 将输入的IP转换
    net = ipaddress.ip_network(network,False)
    # 一个IP一个线程，并记录总共调用了多少个线程
    for i in net:
        add = str(i)                                        
        num+=1
        t = threading.Thread(target=ping_ip,args=(add,))    # 创建多线程，使用ping_ip函数，传入ip作为参数
        t.start()
    # 死循环，等待所有线程结束后打印
    while(True):
        if(ip_num >= num):
            print("共扫描 ",ip_num," 个IP")
            print("存活 ",ip_alives," 个IP")
            print("[GG]感谢使用HCscan！")
            write_in(net)
            break
 
