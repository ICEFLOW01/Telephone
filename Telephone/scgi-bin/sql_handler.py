#!/usr/bin/env python
#-*-coding:utf-8-*a-
import MySQLdb
import hash
class sql():
	def __init__(self,host='172.16.20.50',user='root',passwd='IceFlow2012',db='Telephone'):
		self.host = host
		self.user = user
		self.passwd = passwd
		self.db = db
		self.sql_object = MySQLdb.connect(host,user,passwd,db)
		self.cur_object = self.sql_object.cursor()
		hash.init_hashtable(db,user,passwd)
	def select(self,info):
		result = hash.get_info(info)
		return result
	def select_all(self):
		tem_list=[]
		self.cur_object.execute("select * from staffs")
		for i in self.cur_object.fetchall():
			tem = list(i)[1:]
			for tem2 in tem:
				tem_list.append(tem2) 
                row = self.cur_object.rowcount
                self.sql_object.commit()
                return [row,tem_list]

	def add(self,a,b,c,d,e,f,g):
		self.cur_object.execute("insert into staffs(Name,Abbreviation,Full,Company,Privation,Extension,Email) values('"+a+"','"+b+"','"+c+"','"+d+"','"+e+"','"+f+"','"+g+"')")
		row = self.cur_object.rowcount
		self.sql_object.commit()
		return row 
	def delete(self,dele_email):
		self.cur_object.execute("delete from staffs where Email = '"+dele_email+"'")
		row = self.cur_object.rowcount
                self.sql_object.commit()
                return row
	def reload_sql(self):
		hash.update_hashtable(self.db,self.user,self.passwd)
	def change(self,alist):
		#alist[0].split(':')[1].split('正在修改中')[0]发过来是一行字符串，索引需要取出其中的邮箱地址
		self.cur_object.execute("update staffs set Name='"+alist[1]+"',Abbreviation='"+alist[2]+"',FULL='"+alist[3]+"',Company='"+alist[4]+"',Privation='"+alist[5]+"',Extension='"+alist[6]+"',Email='"+alist[7]+"' where Email ='"+alist[0].split(':')[1].split('正在修改中')[0]+"'")
		row = self.cur_object.rowcount
		self.sql_object.commit()
		return row
