import time
import socket

def get_ip_by_name(domain):
    '''
    提供域名转ip的功能，利用socket.gethostbyname，返回str
    在该程序中并没有被调用
    '''
    try:
        '''将域名转换为IP'''
        return socket.gethostbyname 
    except Exception as e:
        print("%s:%s"%(domain, e))

def port_scan(ip, port_list, timeout):
    '''
    端口扫描核心代码
    '''
    ''' START_MSG = "" '''
    OPEN_MSG = "% 6d [OPEN]"
    result_list = list()

    for port in port_list:
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
    return result_list


def all_port_scan(ip, start_port = 1, end_port = 65535, timeout=3):
    '''
    扫描所有的端口(1-65535)，返回一个包含所有开放的端口list，可以通过参数start_port和参数end_port自定义开始端口和结束端口
    '''
    port_list = range(start_port,end_port+1)
    result_list =  port_scan(ip, port_list, timeout)
    return result_list

def value_port_scan(ip, port_list, timeout):
    result_list = port_scan(ip, port_list, timeout)
    return result_list