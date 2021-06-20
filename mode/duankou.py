import ipaddress
import time
import socket
import threading

result_list = list()
scan_num = 0
port_l = list()
thread_num = 0

def port_scan(ip, port_list, thread, timeout):
    '''
    端口扫描核心代码
    '''
    global scan_num
    global port_l
    global thread_num 

    if(port_list == 'all_port' or port_list == ''):
        port_list = list(range(1,65536))
    elif(port_list == 'simple_port'):
        port_list = [80,8080]
    elif(port_list == 'often_port'):
        port_list = [8080,100]
    
    port_num = len(port_list)
    net = ipaddress.ip_network(ip,False)
    for i in net:
        ip_addr = str(i)
        j=0
        port_l = port_list
        while(True):
            if(thread_num < thread):
                t = threading.Thread(target=scan,args=(ip_addr,timeout))
                t.start()
                thread_num+=1
            if(len(port_l)==0):
                break
            

def scan(ip,timeout):
    global result_list
    global port_l
    global scan_num
    global thread_num
    OPEN_MSG = "% 6d [OPEN]"

    while(len(port_l)!=0):
        port = port_l[0]
        port_l.remove(port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result_code = s.connect_ex((ip, port)) #开放放回0
            if result_code == 0:
                print(OPEN_MSG % port)
                result_list.append(port)
            else:
                continue
        except Exception as e:
            print(e)
        finally:
            s.close()
        scan_num+=1
        thread_num-=1

    return result_list