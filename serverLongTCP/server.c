#include"my.h"

evutil_socket_t listener;//定义套接字描述符变量；
struct event_base *base;
struct event *listen_event;
struct event *end_server_event;

int server_end_release()
{
    int i = 0;
    
    hash_table_release();
    
    for(i=0; i<65535; i++)
    {
        if(client_mes[i].read_event)
        {
            event_del(client_mes[i].read_event);
            event_free(client_mes[i].read_event);
            printf("***1\n");
        }
        if(client_mes[i].write_event)
        {
            event_del(client_mes[i].write_event);
            event_free(client_mes[i].write_event);
            printf("***2\n");
        }
    }
    
    event_del(end_server_event);
    event_free(end_server_event);
    
    event_del(listen_event);
    event_free(listen_event);
    
    event_base_free(base);
    
    return 0;
}

void server_end(evutil_socket_t fd, short event, void *arg)
{
    //do something;
    char buf[64] = {0};
    int ret = read(0, buf, sizeof(buf)-1);
    if(ret < 0)
    {
        perror("end server");
        exit(-1);
    }
    if(strncmp(buf, "quit", 4) == 0)
    {
        printf("Server end!\n");
        server_end_release();
        exit(0);
    }
}

void write_cb(int fd, short event, void*arg)
{
    int w_ret = write(fd, client_mes[fd].buf+client_mes[fd].had_len, client_mes[fd].total_len-client_mes[fd].had_len);
    if(w_ret == client_mes[fd].total_len - client_mes[fd].had_len)
    {
        event_del(client_mes[fd].write_event);
        event_free(client_mes[fd].write_event);
        memset(&client_mes[fd], 0, sizeof(CLIENT_MES));
		//shutdown(fd, SHUT_RDWR );
        //close(fd);
    }
    else if(w_ret>0 && w_ret<client_mes[fd].total_len - client_mes[fd].had_len)
    {
        client_mes[fd].had_len =+ w_ret;
    }
    else
    {
        return;
    }
}

int write_mes(int fd, char*buf, QA_HEAD qa_head, void*arg)
{
    struct event_base *base = (struct event_base*)arg;
    
    int w_ret = write(fd, buf, qa_head.package_len);//发包；
    if(w_ret = qa_head.package_len)//判断是否发送完整；
    {
        return 0;
    }
    else if(w_ret>0 && w_ret<qa_head.package_len)
    {
        client_mes[fd].id_flag = qa_head.package_id;
        client_mes[fd].had_len = w_ret;
        client_mes[fd].total_len = qa_head.package_len;
        memcpy(client_mes[fd].buf, buf, qa_head.package_len);
        //创建并绑定event；
        struct event *write_event;
        write_event = event_new(base, fd, EV_WRITE|EV_PERSIST, write_cb, (void*)base);
        event_add(write_event, NULL);//添加对象，NULL表示无超时设置；
        client_mes[fd].write_event = write_event;
    }
    else
    {
        perror("write_mes write");
        return -1;
    }
}

int exception_handling(int fd, char*buf, int len, void*arg)
{
    if(len == client_mes[fd].total_len-client_mes[fd].had_len)//判断是否可以补全为完整的信息段；
    {
        memcpy(client_mes[fd].buf+client_mes[fd].had_len, 
               buf, 
               client_mes[fd].total_len-client_mes[fd].had_len
               );
               
        data_processing(fd, client_mes[fd].buf, len, arg);//查询数据，发送数据；
    }
    else
    {
        memcpy(client_mes[fd].buf+client_mes[fd].had_len, 
                buf, 
                len
                );
                
        client_mes[fd].had_len =+ len;
    }
    
    return 0;
}

int data_processing(int fd, char*line, int len, void*arg)
{
    struct event_base *base = (struct event_base*)arg;
    QR_HEAD *head;
    
    QA_HEAD qa_head;
    memset(&qa_head, 0, sizeof(QA_HEAD));
    qa_head.package_len = 232;
    qa_head.package_id = 11;
    
    HashNode **getinfo;//储存查询结果信息；
    char buf[sizeof(QA_HEAD)+4096];
    
    head = (QR_HEAD*)line;
    if(len < head->package_len)
    {   
        client_mes[fd].total_len = head->package_len;
        memcpy(client_mes[fd].buf+client_mes[fd].had_len, 
                buf, 
                len
                );
                
        client_mes[fd].had_len =+ len;
        return -1;
    }
    printf("len %d\n", head->package_len);
    printf("id %d\n", head->package_id);
    printf("fd = %u, readline:%s", fd, (char*)(line+sizeof(QR_HEAD)));
    fflush(stdout);
    if(head->package_id == 9)//检测是不是reload包，通知重载hash表；
    {
        update_hash_table();//重载hash表内容；
        return -1;
    }
    
	
    getinfo = hash_table_lookup(line+sizeof(QA_HEAD));//查询hash表;
    if(getinfo == NULL)//如果没有查询到相应的信息，设置包长度为包头长度；
    {
        qa_head.package_len = 8;
        memcpy(buf, &qa_head, sizeof(QA_HEAD));
    }
    else
    {
        int i = 0;
        while(getinfo[i])//循环往包里添加查询到的数据；
        {
            memcpy(buf+sizeof(QA_HEAD)+i*sizeof(INFOR), getinfo[i]->infor, sizeof(INFOR));
            i++;
        }
        qa_head.package_len = sizeof(QA_HEAD)+i*sizeof(INFOR);
        memcpy(buf, &qa_head, sizeof(QA_HEAD));
    }
    //将查询到的信息回写给client端；
	write_mes(fd, buf, qa_head, arg);

    return 0;
}

int judgment_existence(int fd)
{
    if(client_mes[fd].had_len == 0)//判断是否已经有不完整信息存在；
    {
        return 0;
    }
    else
    {
        return -1;
    }
    
    return 0;
}

void read_cb(int fd, short event, void*arg)//读取套接字里的内容；
{
    #define MAX_LINE 4096
    char line[MAX_LINE+1]={0};
    
    int n=0;
    
    n = read(fd, line, sizeof(line)-1);//读取套接字中的内容；
    if(n<0)
    {
        perror("read_cb read\n");
        return ;
    }
    else if(n==0)
    {
        event_del(client_mes[fd].read_event);
        event_free(client_mes[fd].read_event);
        if(client_mes[fd].write_event) 
        {
            event_del(client_mes[fd].write_event);
            event_free(client_mes[fd].write_event);
        }
        
        printf("fd = %d,connecton closed!\n", fd);
        memset(&client_mes[fd], 0, sizeof(CLIENT_MES));
		shutdown(fd, SHUT_RDWR );
        close(fd);
        return;
    }
    else
    {
        int ret = judgment_existence(fd);//返回0表示没有不完整信息存在；
        if (ret == 0)
        {
            data_processing(fd, line, n, arg);
        }
        else
        {
            //异常处理函数；
            exception_handling(fd, line, n, arg);
        }
    }
}

void do_accept(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = (struct event_base*)arg;
    evutil_socket_t fd;//定义连接套接字描述符变量；
    struct sockaddr_in sin;//定义地址族结构体变量；
    socklen_t slen = 1;
    
    fd = accept(listener, (struct sockaddr*)&sin, &slen);//接受连接；
    if (fd<0)
    {printf("%d\n",fd);
        perror("accept");
        return;
    }
    if(fd>TCP_MAX)//判断是否大于最大的描述符上限；
    {
        perror("fd>TCP_MAX\n");
        return;
    }
    printf("ACCEPT:fd = %u\n", fd);
    
    evutil_make_socket_nonblocking(fd);//设置套接字为不阻塞；

    //创建并绑定event；
    struct event *read_event;
    read_event = event_new(base, fd, EV_READ|EV_PERSIST, read_cb, (void*)base);
    event_add(read_event, NULL);//添加对象，NULL表示无超时设置；    
    client_mes[fd].read_event = read_event;
}

int tcp_init()
{
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
    
    return 0;
}

int server_init()
{
    int ret;
    
    memset(client_mes, 0, sizeof(client_mes));
    
    ret = init_hash_table();//初始化hash表；
    if(ret)
    {
        printf("init_hash_table error!\n");
    }
    
    return 0;
}

int main(int argc, char*argv[])
{    
    server_init();
    
    tcp_init();
    
    base = event_base_new();//创建event_base对象；
    assert(base != NULL);
    
    //创建并绑定event；
    
    end_server_event = event_new(base, 0, EV_READ|EV_PERSIST, server_end, (void*)base);
    listen_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);
    event_add(listen_event, NULL);//添加对象，NULL表示无超时设置；
    event_add(end_server_event, NULL);
    event_base_dispatch(base);//启用循环;
    
  //  server_end();//暂时未使用；
  
    
    return 0;
}