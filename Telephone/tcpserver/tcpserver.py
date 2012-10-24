#!/usr/bin/env python
#-*-coding:utf-8-*-
import select
import socket
import errno
import hash
import struct
serversocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
serversocket.bind(('172.16.16.10',8000))
serversocket.listen(1)
serversocket.setblocking(0)

epoll = select.epoll()
epoll.register(serversocket.fileno(),select.EPOLLIN|select.EPOLLET)

hash.init_hashtable('Telephone','root','IceFlow2012')
try:
   connections = {};addresses = {};datalist = {};backmsg = {}
   while True:
	 events = epoll.poll(1)#查询epoll对象 是否有事件被触发 参数表示1秒 等待一秒看是否有事件发生
	 for fileno,event in events:
	     if fileno == serversocket.fileno():
		try:
   		   #while True:	
		 	connection,address = serversocket.accept()
		 	print "accept connection from %s, %d, fd = %d" % (address[0], address[1], connection.fileno())
		 	connection.setblocking(0)
		 	epoll.register(connection.fileno(),select.EPOLLIN|select.EPOLLET)
		 	connections[connection.fileno()] = connection
		 	addresses[connection.fileno()] = address
			datalist[connection.fileno()] = ''
		except socket.error:
			pass
	     elif event & select.EPOLLIN:#系统内的事件比较 做与运算
		recv_result = ''
		try:
		    while True:
			  recv_result += connections[fileno].recv(1024)
		except socket.error, msg:
			  pass
		datalist[fileno] = recv_result#把接收到结果赋给该事件
		recv_pack = struct.unpack('ii64s',datalist[fileno])
		if recv_pack[1] == 10:
			check = hash.get_info(recv_pack[2].replace('\0','').strip())#把空字符转换成空格，再去掉空格
			if check != None:
				check_rel = check.split('\\')
				tem = []
				for val in check_rel:
					tem.append(struct.pack('32s',val))#把每个返回结果都打包成32个字节
				send_val = ''.join(tem)#把列表整合成字符串
				backmsg[fileno] = struct.pack('ii224s',232,11,send_val)
				epoll.modify(fileno, select.EPOLLOUT | select.EPOLLET)
			else:
				backmsg[fileno] = struct.pack('ii224s',8,11,'\0')
				epoll.modify(fileno, select.EPOLLOUT | select.EPOLLET)
		elif recv_pack[1]==9:
			hash.update_hashtable('Telephone', 'root', 'IceFlow2012')
			epoll.unregister(fileno)
		
	     elif event & select.EPOLLHUP:
		epoll.unregister(fileno)
		connections[fileno].close()
		del connections[fileno]
	     elif event & select.EPOLLOUT:
		try:
		   while len(backmsg[fileno])>0:
			sendlen = connections[fileno].send(backmsg[fileno])
			backmsg[fileno] = backmsg[fileno][sendlen:]
		except socket.error:
			pass
		if len(backmsg[fileno]) == 0:
			epoll.modify(fileno,select.EPOLLIN | select.EPOLLET)#重新注册对读的关注
			#connections[fileno].shutdown(socket.SHUT_RDWR)#shutdown是可选的.shutdown调用会通知客户端socket没有更多的数据应该被发送或接收，并会让功能正常的客户端关闭自己的socket连接。
#except KeyboardInterrupt:
 #    raise
finally:
     epoll.unregister(serversocket.fileno())
     epoll.close()
     serversocket.close()
