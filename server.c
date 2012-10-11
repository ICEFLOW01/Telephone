#include"my.h"

int main(int argc, char*argv[])
{
    int ret;
    ret = init_hash_table();//初始化hash表；
    if(ret)
    {
        printf("init_hash_table error!\n");
    }
    
    evutil_socket_t listener;//定义套接字描述符变量；
    listener = socket(AF_INET, SOCK_STREAM, 0);//建立套接字；
    assert(listener > 0);
    
    evutil_make_listen_socket_reuseable(listener);//
    
    //定义地址族结构；
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;   
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(LISTEN_PORT);//设定端口号；
    
    if(bind(listener,(struct sockaddr*)&sin, sizeof(sin))<0)//绑定；
    {
        perror("bind");
        return 1;
    }
    
    if(listen(listener, LISTEN_BACKLOG) < 0)//监听；
    {
        perror("listen");
        return 1;
    }
    printf("Listening...\n");
    
    evutil_make_socket_nonblocking(listener);//设置套接字为不阻塞；
    
    struct event_base *base = event_base_new();//创建event_base对象；
    assert(base != NULL);
    
    //创建并绑定event；
    struct event *listen_event;
    listen_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);
    event_add(listen_event, NULL);//添加对象，NULL表示无超时设置；
    event_base_dispatch(base);//启用循环；
    
    printf("The End.");
    return 0;
}

void do_accept(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = (struct event_base*)arg;
    evutil_socket_t fd;//定义连接套接字描述符变量；
    struct sockaddr_in sin;//定义地址族结构体变量；
    socklen_t slen;
    
    fd = accept(listener, (struct sockaddr*)&sin, &slen);//接受连接；
    if (fd<0)
    {
        perror("accept");
        return;
    }
    if(fd>FD_SETSIZE)//判断是否大于最大的描述符上限；
    {
        perror("fd>FD_SETSIZE\n");
        return;
    }
    printf("ACCEPT:fd = %u\n", fd);
    
    //产生和绑定新事件（bufferevent内部有read/write和缓冲区）；
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    
    bufferevent_setcb(bev, read_cb, NULL, error_cb, arg);//设置回调函数；
    bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);
}

void read_cb(struct bufferevent*bev, void*arg)//循环读取套接字里的内容；
{
    #define MAX_LINE 256
    char line[MAX_LINE+1]={0};
    QR_HEAD *head;
    QA_HEAD qa_head;
    memset(&qa_head, 0, sizeof(QA_HEAD));
    qa_head.package_len = 232;
    qa_head.package_id = 11;
    HashNode **getinfo;//储存查询结果信息；
    int n;
    int i=0; 
    
    char *buf = malloc(sizeof(QA_HEAD)+4096);
    
    evutil_socket_t fd = bufferevent_getfd(bev);//获取套接字描述符；
    while(n = bufferevent_read(bev, line, MAX_LINE), n>0)//读取套接字中的内容；
    {
        head = (QR_HEAD*)line;
        
        printf("len %d\n", head->package_len);
        printf("id %d\n", head->package_id);
        printf("fd = %u, readline:%s", fd, (char*)(line+sizeof(QR_HEAD)));
        if(head->package_id == 9)//检测是不是reload包，通知重载hash表；
        {
            update_hash_table();//重载hash表内容；
            continue;
        }
        getinfo = hash_table_lookup(line+sizeof(QA_HEAD));//查询hash表;
        if(getinfo == NULL)//如果没有查询到响应的信息，设置包长度为包头长度；
        {
            qa_head.package_len = 8;
            memcpy(buf, &qa_head, sizeof(QA_HEAD));
        }
        else
        {
            i = 0;
            while(getinfo[i])//循环往包里添加查询到的数据；
            {
                memcpy(buf+sizeof(QA_HEAD)+i*sizeof(INFOR), getinfo[i]->infor, sizeof(INFOR));
                i++;
            }
            qa_head.package_len = sizeof(QA_HEAD)+i*sizeof(INFOR);
            memcpy(buf, &qa_head, sizeof(QA_HEAD));
        }
        bufferevent_write(bev, buf, sizeof(QA_HEAD)+4096);//发包；
    }
}

void error_cb(struct bufferevent *bev, short event, void*arg)//异常处理函数；
{
    evutil_socket_t fd = bufferevent_getfd(bev);
    printf("fd = %u,", fd);
    if(event & BEV_EVENT_TIMEOUT)
    {
        printf("timed out\n");
    }
    else if(event & BEV_EVENT_EOF)
    {
        printf("connection closed\n");
    }
    else if(event & BEV_EVENT_ERROR)
    {
        printf("some other error\n");
    }
    bufferevent_free(bev);//释放资源；
}