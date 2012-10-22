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
#include<sys/types.h>
#include<unistd.h>
#include<fcntl.h>

#define HASH_TABLE_MAX_SIZE 10000//哈希数组大小；
#define TCP_MAX 60000//设定最大的连接数；
#define LISTEN_PORT 5000
#define LISTEN_BACKLOG 32

typedef struct client_mes_struct
{
		int id_flag;             //标志位；
		int total_len;             //包长度；
        int had_len;          //已经存取长度；
		char buf[4096];      //保存信息的buf；
        struct event *write_event;
        struct event *read_event;
}CLIENT_MES;

CLIENT_MES client_mes[65535];

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

int tcp_init();
void write_ser();
void read_ser();
int read_stdin(char*data, int len);
void unpackage(char*buf);
int tcp_close();

int server_init();
int tcp_init();
void do_accept(evutil_socket_t listener, short event, void *arg);
void read_cb(int fd, short event, void*arg);
int judgment_existence(int fd);
int data_processing(int fd, char*line, int len, void*arg);
int exception_handling(int fd, char*buf, int len, void*arg);
int write_mes(int fd, char*buf, QA_HEAD qa_head, void*arg);
void write_cb(int fd, short event, void*arg);

void hash_table_init();
unsigned int hash_table_hash_str(const char*skey);
void hash_table_release();
int update_hash_table();
int init_hash_table();
void display_header();
void hash_table_insert(const char* skey, INFOR* nvalue);
HashNode** hash_table_lookup(char* skey);