#include"my.h"

int sockfd;//连接套接字描述符；

int main()
{
    int ret = -1;
    
    printf("与服务器正在连接...\n");
    ret = function();//客户端功能展开函数；
    if(ret != 0)
    {
        perror("function error\n");
        return -1;
    }
    return 0;
}

int function()
{
    int ret = -1;
    pthread_t tid1 = -1;//定义线程ID；
    pthread_t tid2 = -1;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("socket error\n");
        return -1;
    }
    //IPv4地址族结构；
    struct sockaddr_in seraddr;
    memset (&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = htons(5000);
    inet_pton(AF_INET, "172.16.18.100", &seraddr.sin_addr.s_addr);//字节序转换；
    //seraddr.sin_port = htons(8000);
   // inet_pton(AF_INET, "172.16.16.10", &seraddr.sin_addr.s_addr);//字节序转换；
    
    ret = connect(sockfd, (struct sockaddr*)&seraddr, sizeof(seraddr));//连接；
    if(ret != 0)
    {
        perror("connect error\n");
        return -1;
    }
    printf("与服务器连接成功！\n");
    ret = pthread_create(&tid1, NULL, write_ser, NULL);//创建往socket套接字写信息的线程；
    if(ret != 0)
    {
        perror("pthread write error\n");
        return -1;
    }
    
    ret = pthread_create(&tid2, NULL, read_ser, NULL);//创建从socket套接字中读取信息的线程；
    if(ret != 0)
    {
        perror("pthread read error\n");
        return -1;
    }
    
    pthread_join(tid1, NULL);//等待线程结束；
    pthread_join(tid2, NULL);
    return 0;
}

void *write_ser()//写数据的线程函数；
{   
    QR_HEAD package_head;//包头；
    memset(&package_head, 0, sizeof(QR_HEAD));
    package_head.package_len = 72;//定长包；
    package_head.package_id = 10;//协议类型；
    char data[64];//包的数据段；
    
    char *buf = malloc(sizeof(QR_HEAD)+64);    
    int ret = -1;
    //循环往套接字里写入数据；
    fflush(stdin);
    printf("查找支持：中文名、简拼、全拼、公司手机号、私人号码、分机号、邮箱！\n退出系统请输入：quit\n");
    printf("input message:");
    while(1)
    {
        fflush(stdout);
        fflush(stdin);
        memset(buf, 0, sizeof(QR_HEAD)+64);
        memcpy(buf, &package_head, sizeof(QR_HEAD));
        memset(data, 0, 64);
        ret = read(0, data, sizeof(data)-1);//从标准输入中读取数据；
        if(ret == -1)
        {   
            perror("write_ser read error\n");
            exit(0);
        }
        if(strncmp(data, "quit", sizeof("quit")-1)==0)
        {
            exit(0);
        }
        fflush(stdout);
        fflush(stdin);
        memcpy(buf+sizeof(QR_HEAD), data, 64);
        ret = write(sockfd, buf, sizeof(QR_HEAD)+64);//把标准输入的数据写入到套接字里面；
        if(ret == -1)
        {
            perror("write_ser write error\n");
            exit(0);
        }
    }
}

void *read_ser()//读数据的线程函数；
{
    int ret = -1;
    char buf[5096];
    //循环从socket套接字里读取数据，直至读取完毕；
    while(1)
    {
        memset(buf, 0, sizeof(buf));
        
        ret = read(sockfd, buf, sizeof(buf)-1);
        if(ret < 0)
        {
            perror("read_ser read error\n");
            exit(0);
        }
        else if(ret == 0)
        {
            printf("\nser end\n");
            fflush(stdout);
            exit(0);
        }
        unpackage(buf);//解包；
    }
}

void unpackage(char*buf)//解析查询结果数据包；
{
    QA_HEAD* change_buf;
    int number;//传回的信息的条数；
    change_buf = (QA_HEAD*)buf;
 // printf("\n******len %d\n******id %d\n", change_buf->package_len, change_buf->package_id);
    if(change_buf->package_id != 11)
    {
        return;
    }
    if(change_buf->package_len == 8)
    {
        printf("你要查询的信息不存在！\n");
    }
    else
    {
        number = (change_buf->package_len-sizeof(QA_HEAD))/224;
        
        while(number--)
        {
            printf("你要查询的信息如下:\n姓名：%s\n简拼：%s\n全拼：%s\n公司电话：%s\n私人电话：%s\n分机号：%s\nEmail：%s\n",
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->myname,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->abbreviation,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->full,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->company,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->privation,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->extension,
                                ((INFOR*)(buf+sizeof(QA_HEAD)+number*224))->emall
                                );
        }
        
    }
    printf("查找支持：中文名、简拼、全拼、公司手机号、私人号码、分机号、邮箱！\n退出系统请输入：quit\n");
    printf("input message:");//提示输入数据；
    fflush(stdout);
}