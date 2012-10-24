#!/usr/bin/env python
#-*-coding:utf-8-*-
import time
import os
import scgi
import MySQLdb
import sql_handler
import urllib
import struct
import re
from   scgi.scgi_server import *
from   page_handler import *

SCGI_INERR='/scgi-bin/inerr'
opt={}
opt['scgisev'] = index
opt[SCGI_INERR]=inerr
opt['first'] = check
opt['add'] = add
opt['del'] = dele
opt['change'] = change
opt['all'] = all_msg
changeby = []
def send():
	connFd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	connFd.connect(("172.16.16.10", 8000))
	send_info = struct.pack('ii64s',8,9,'reload')
	connFd.send(send_info)
	connFd.close()
	connFd_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	connFd_c.connect(("172.16.18.100",5000))
	connFd_c.send(send_info)
	connFd_c.close()

class MyHandler(SCGIHandler):
    def produce(self,env,bodysize,input,output) :
	try:
		alist = []
		code = urllib.unquote(env['REQUEST_URI'])
		print code
		url = code.split('/')
		if '?' not in env['REQUEST_URI']:
			if  code == '/scgi-bin/scgisev':
				opt['scgisev'](env,bodysize,input,output)
			elif  code == '/scgi-bin/first':
				opt['first'](env,bodysize,input,output)
			elif  code == '/scgi-bin/add':
				opt['add'](env,bodysize,input,output)
			elif  code == '/scgi-bin/del':
				opt['del'](env,bodysize,input,output)
			elif  code == '/scgi-bin/change':
				opt['change'](env,bodysize,input,output)
			elif code == '/scgi-bin/all':
				result = sql_object.select_all()
				opt['all'](env,bodysize,input,output,result[1])
		elif '?' in  code:
			second_url = url[2].split('?')
			print second_url[1].split('&')
			print second_url
			if '&' in  code:
				result_url = second_url[1].split('&')
				for a in result_url:
					b=a.split('=')
					alist.append(b[1])
			else:
				alist.append(second_url[1].split('=')[1])
			try:
				global changeby
				if second_url[0] == 'first':#查询
					select_res = sql_object.select(alist[0])
					if select_res == None:
						select_error(env,bodysize,input,output)
					else:
						result1 = select_res.split('\\')	
						result = result1[:-1]#去掉最后一个空格
						select_finsh(env,bodysize,input,output,result)
				if second_url[0] == 'add':#添加
					if alist[0]=='' or alist[1]=='' or alist[2]=='' or alist[6]=='':
						no_null(env,bodysize,input,output)
					else:
						row = sql_object.add(alist[0],alist[1],alist[2],alist[3],alist[4],alist[5],alist[6])
						if row >0:
							add_finsh(env,bodysize,input,output)
							sql_object.reload_sql()#数据库重载
							try:
						   		send()#数据变化发送包
							except socket.error:
						   		print '请检查TCP server是否开启'
				if second_url[0] == 'del':#删除
					if len(alist)>2:
						row1 = sql_object.delete(alist[0])
						if row1>0:
							dele_finsh(env,bodysize,input,output)
							sql_object.reload_sql()
							try:
						   	   send()
							except socket.error:
						   	   print '请检查TCP server是否开启'
						else:
							dele_error(env,bodysize,input,output)	
					else:
						select_res = sql_object.select(alist[0])
                                        	if select_res == None:
                                               		select_error(env,bodysize,input,output)
						else:
							result1 = select_res.split('\\')
                                                	result = result1[:-1]
							del_begin(env,bodysize,input,output,result)

				if second_url[0] == 'change':#改变
					if len(alist)>2:
					       if alist[1]=='' or alist[2]=='' or alist[3]=='' or alist[7]=='':
							no_null(env,bodysize,input,output)
					       else:
							row2 = sql_object.change(alist)
							if row2>0:
								change_finsh(env,bodysize,input,output)
								sql_object.reload_sql()
								try:
							   		send()
								except socket.error:
						   	   		print '请检查TCP server是否开启'
							else:
								change_error(env,bodysize,input,output)			
				        else:
						if alist[0] == 'want_to_change':
							select_res = sql_object.select(alist[1])
							result1 = select_res.split('\\')
							result = result1[:-1]
							result.append(alist[1])
							change_on(env,bodysize,input,output,result)
						else:
							select_res = sql_object.select(alist[0])
							print select_res
                                        		if select_res == None:
                                               			select_error(env,bodysize,input,output)
							else:
                                               			result1 = select_res.split('\\')
								result = result1[:-1]
                                               			#change_on(env,bodysize,input,output,result)
								change_begin(env,bodysize,input,output,result)
			except MySQLdb.IntegrityError,e:
				if e[0] == 1062:#数据库错误代号1062为重复添加
				   add_error(env,bodysize,input,output,e[1].split('\'')[1])#把错误内容发送到网页
	except KeyError :
		opt[SCGI_INERR](env,bodysize,input,output)

if __name__ == '__main__' :
    sql_object = sql_handler.sql()
    server = SCGIServer(handler_class=MyHandler,host='127.0.0.1',port=3000)
    server.serve()

