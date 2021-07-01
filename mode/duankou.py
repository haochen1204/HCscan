import ipaddress
import copy
import socket
import threading
import xlwt
import time

result_list = list()
port_l = list()
thread_num = 0

def port_scan(ip, port_list, thread, timeout, export):
    '''
    端口扫描核心代码
    '''
    global port_l
    global thread_num 
    ip_num = 0

    if(port_list == 'all_port' or port_list == ''):
        port_list = list(range(1,65536))
    elif(port_list == 'simple_port'):
        port_list = [21,22,80,137,161,443,445,1900,3306,3389,5353,8080]
    elif(port_list == 'often_port'):
        port_list = [21,22,23,25,53,53,80,81,110,111,123,123,135,137,139,61,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,27017,37777,50000,50070,61616]
    
    port_num = len(port_list)
    net = ipaddress.ip_network(ip,False)
    for i in net:
        ip_addr = str(i)
        ip_num+=1
        port_l = port_list
        while(True):
            if(thread_num < int(thread)):
                t = threading.Thread(target=scan,args=(ip_addr,timeout))
                t.start()
                thread_num+=1
            if(len(port_l)==0):
                break
    print("\n共扫描"+str(ip_num)+"个IP，"+str(port_num)+"个端口。")
    print("发现 "+str(len(result_list))+" 个端口开放")
    print("[GG]感谢使用HCscan！")
    if export == True:
        write_in(ip)
    return result_list        

def write_in(ip):
    global result_list
    work_Book=xlwt.Workbook(encoding='utf-8')
    sheet=work_Book.add_sheet('端口扫描')
    sheet.write(0,0,'开放端口：')
    result_lists=copy.deepcopy(result_list)
    result_lists.reverse()
    i=1 
    while len(result_lists)!=0:
        msg=result_lists.pop()
        msglist = msg.split(':')
        sheet.write(i,1,str(msglist.pop()))
        sheet.write(i,0,str(msglist.pop()))
        i+=1
    name = str(time.strftime("%Y%m%d %H-%M-%S", time.localtime())) + '端口扫描.xls'
    work_Book.save(name)

def scan(ip,timeout):
    global result_list
    global port_l
    global thread_num
    OPEN_MSG = "% 6d [OPEN]"

    while(len(port_l)!=0):
        port = port_l[0]
        try:
            port_l.remove(port)
        except:
            e = IndexError
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(int(timeout))
            result_code = s.connect_ex((ip, port)) #开放放回0
            if result_code == 0:
                print('[+] '+ip+'  '+ OPEN_MSG % port)
                msg = ip+':'+str(port)
                result_list.append(msg)
            else:
                continue
        finally:
            s.close()
        thread_num-=1
    