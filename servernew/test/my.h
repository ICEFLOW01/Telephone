#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<assert.h>
#include<string.h>
#include<event2/event.h>
#include<event2/bufferevent.h>
#include<mysql/mysql.h>
#include<time.h>
#include <locale.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<pthread.h>

#define HASH_TABLE_MAX_SIZE 10000//哈希数组大小；

typedef struct Infor_Struct//员工信息结构体；
{
    char myname[32];
    char abbreviation[32];
    char full[32];
    char company[32];
    char privation[32];
    char extension[32];
    char emall[32];
}INFOR;

typedef struct HashNode_Struct//定义哈希数组类型；
{
    char* sKey;
    INFOR* infor;
    struct HashNode_Struct*pNext;
}HashNode;

typedef struct QR_head//定义请求包头；
{
    int package_len;
    int package_id;
}QR_HEAD;

typedef struct QA_head
{
    int package_len;
    int package_id;
}QA_HEAD;

int function();//client端功能展开函数；
void *write_ser();//往套接字里写数据函数；
void *read_ser();//从套接字读取信息函数；
void unpackage(char*buf);//解包函数；

void display_header();
void hash_table_insert(const char* skey, INFOR* nvalue);
HashNode** hash_table_lookup(char* skey);
int init_hash_table();
int update_hash_table();
void hash_table_release();
#define LISTEN_PORT 5000
#define LISTEN_BACKLOG 32

//函数的声明；
void do_accept(evutil_socket_t listener, short event, void*arg);
void read_cb(struct bufferevent*bev, void*arg);
void error_cb(struct bufferevent*bev, short event, void*arg);
void write_cb(struct bufferevent*bev, void*arg);//暂时未使用；