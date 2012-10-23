#include"my.h"

int sockfd;//连接套接字描述符；
char ip[256] = {0};
int port;

int tcp_close()
{
    shutdown(sockfd, SHUT_RDWR );
    close(sockfd);
    return 0;
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
}

void read_ser()//读数据的函数；
{
    int ret = -1;
    char buf[4096];
    //循环从socket套接字里读取数据，直至读取完毕；
	char save_buf[4096] = {0};
    QA_HEAD* change_buf;
	int sum = 0;
    
    while(1)
    {        
		memset(buf, 0, sizeof(buf));
        ret = read(sockfd, buf, sizeof(buf)-1);
        if(ret < 0)
        {
            perror("read_ser read error\n");
            exit(0);
        }
        else if(ret == ((QA_HEAD*)buf)->package_len || ret == ((QA_HEAD*)save_buf)->package_len)
        {
            memcpy(save_buf+sum, buf, ret);
            break;
        }
		else
		{
			memcpy(save_buf+sum, buf, ret);
			sum =+ ret;
		}
    }
	unpackage(save_buf);//解包
}

int read_stdin(char*data, int len)
{
	int ret = -1;
	fflush(stdout);
    fflush(stdin);

    printf("查找支持：中文名、简拼、全拼、公司手机号、私人号码、分机号、邮箱！\n退出系统请输入：quit\n");
    printf("input message:");
    fflush(stdout);
	/*ret = read(0, data, len-1);//从标准输入中读取数据；
    if(ret == -1)
    {   
        perror("write_ser read error\n");
        exit(0);
    }
    if(strncmp(data, "quit", sizeof("quit")-1)==0)
    {
        exit(0);
    }*/
	fflush(stdout);
    fflush(stdin);
    memcpy(data, "lgj", sizeof("lgj"));
   // sleep(1);
	return 0;
}


void write_ser()//写数据的函数；
{   
    QR_HEAD package_head;//包头；
    memset(&package_head, 0, sizeof(QR_HEAD));
    package_head.package_len = 72;//定长包；
    package_head.package_id = 10;//协议类型；
    char data[64];//包的数据段；
    
    char buf[sizeof(QR_HEAD)+64] = {0};    
    int ret = -1;
    
    fflush(stdout);
    fflush(stdin);

    memcpy(buf, &package_head, sizeof(QR_HEAD));
    memset(data, 0, 64);
	
    read_stdin(data, 64);
		
    fflush(stdout);
    fflush(stdin);
    memcpy(buf+sizeof(QR_HEAD), data, 64);
    int write_len = sizeof(QR_HEAD)+64;
    int sum = 0;
	while(1)
    {
        ret = write(sockfd, buf+sum, write_len);//把标准输入的数据写入到套接字里面；
        if(ret == -1)
        {
            perror("write_ser write error\n");
            exit(0);
        }
		else if(ret == sizeof(QR_HEAD)+64 || sum == sizeof(QR_HEAD)+64)
		{
			break;
		}
		else
		{
			sum =+ret;
            write_len =- ret;
		}
    }
}

int tcp_init()
{
    int ret = -1;
    
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
    seraddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &seraddr.sin_addr.s_addr);//字节序转换；
    
    ret = connect(sockfd, (struct sockaddr*)&seraddr, sizeof(seraddr));//连接；
    if(ret != 0)
    {
        perror("connect error\n");
        exit(0);
    }
    printf("与服务器连接成功！\n");
    
    return 0;
}

int main(int argc, char* argv[])
{
    int ret = -1;;
int i = 0;
    if(argc<3)
	{
		printf("Usage:%s option\n",argv[0]);
		printf("for example:%s ip port \n",argv[0]);
		return 0;
	}
	sscanf(argv[1], "%s", ip);
    sscanf(argv[2], "%d", &port);
	while(i<60000)
	{
        tcp_init();
        write_ser();
        read_ser();
        //tcp_close();
        i++;
	}
    sleep(100);
    return 0;
}

