#include"my.h"

HashNode*hashTable[HASH_TABLE_MAX_SIZE];//定义哈希数组；
int hash_table_size;//哈希表实际大小；
int res;
MYSQL my_connection;//定义MYSQL结构，连接句柄；
MYSQL_RES *res_ptr;//保存检索出的列；
MYSQL_ROW sqlrow;//保存返回的其中一列；

void hash_table_init()//初始化哈希表大小和哈希数组；
{
    hash_table_size = 0;
    memset(hashTable, 0, sizeof(HashNode*)*HASH_TABLE_MAX_SIZE);
}

unsigned int hash_table_hash_str(const char*skey)//字符串哈希算法函数；
{
    const signed char*p = (const signed char*)skey;
    unsigned int h = *p;
    if(h)
    {
        for(p+=1; *p!='\0'; p++)
        {
            h = (h<<5) - h + *p;
        }
    }
    return h;
}

/*
int main()//测试函数；
{
  //  char DBName[] = "Telephone";
  //  char DBUserName[] = "root";
  //  char DBUserPassword[] = "IceFlow2012";
    init_hash_table();
    update_hash_table();
    printf("哈希表实际大小：%d\n", hash_table_size);
    char a[256];
    printf("请输入要查询的信息：");
    scanf("%s", a);
    HashNode*ptest;
    ptest = hash_table_lookup(a);
    printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n", ptest->infor->myname,
                                        ptest->infor->abbreviation,
                                        ptest->infor->full,
                                        ptest->infor->company,
                                        ptest->infor->privation,
                                        ptest->infor->extension,
                                        ptest->infor->emall);
    return 0;
}
*/

//free the memory of the hash table
void hash_table_release()//重载hash表数据之前，释放之前hash表资源；
{
    int i;
    for(i = 0; i < HASH_TABLE_MAX_SIZE; ++i)
    {
        if(hashTable[i])
        {
            HashNode* pHead = hashTable[i];
            while(pHead)
            {
                HashNode* pTemp = pHead;
                pHead = pHead->pNext;
                if(pTemp)
                {
                    free(pTemp->sKey);
                    free(pTemp->infor);
                    free(pTemp);
                }
            }
        }
    }
}


int update_hash_table()//重载hash表；
{
    hash_table_release();
    init_hash_table();
    return 0;
}

int init_hash_table()//初始化hash表；
{
    char mysql_server_ip[] = "172.16.20.50";
    char mysqlDB_name[] = "Telephone";
    char mysql_name[] = "root";
    char mysql_password[] = "IceFlow2012";

    hash_table_init();//初始化哈希表大小和哈希数组；
    mysql_init(&my_connection);//初始化MYSQL结构；
    //数据库的连接；
    if(mysql_real_connect(&my_connection, 
                            mysql_server_ip, 
                            mysql_name,
                            mysql_password,
                            mysqlDB_name,
                            0,
                            NULL,
                            0))
    {
        printf("Database connection success\n");
        res = mysql_query(&my_connection, "select * from staffs");//查询数据库信息；
        if(res)
        {
            printf("database select error:%s\n", mysql_error(&my_connection));
            return -1;
        }
        else
        {
            res_ptr = mysql_store_result(&my_connection);//将检索到的数据储存到本地；
            if(res_ptr)
            {
                printf("Retrieved %lu rows\n", (unsigned long)mysql_num_rows(res_ptr));//打印取回多少行；
                display_header();//建立哈希表功能函数；
                if(mysql_errno(&my_connection))
                {
                    fprintf(stderr, "Retrive error:%s\n", mysql_error(&my_connection));
                    return -1;
                }
            }
            mysql_free_result(res_ptr);//释放资源；
        }
        mysql_close(&my_connection);
        printf("Database connection closed.\n");
    }
    else
    {
        fprintf(stderr, "Connection failed\n");
        if(mysql_errno(&my_connection))
        {
            fprintf(stderr,"Connection error %d:%s\n", 
                                        mysql_errno(&my_connection), //错误消息编号；
                                        mysql_error(&my_connection));//返回包含错误消息的、由NULL终结的字符串；
            return -1;
        }
    }
    return 0;
}

void display_header()//建立哈希表；
{
    unsigned int num_fields;
    unsigned int i;
    MYSQL_ROW row;
    INFOR* NewInfor;
    
    num_fields = mysql_num_fields(res_ptr);//返回结果集合中字段的数；
    while(row = mysql_fetch_row(res_ptr))//检索集合并且返回下一行；
    {   
        for(i=1; i<num_fields; i++)//循环给每一行的每一个字段的信息进行hash计算，放入hash表；
        {
            NewInfor = malloc(sizeof(INFOR));//给新的节点分配内存空间；
            memset(NewInfor, 0, sizeof(INFOR));
            
            strcpy(NewInfor->myname, row[1]?row[1]:"NULL");
            strcpy(NewInfor->abbreviation, row[2]?row[2]:"NULL");
            strcpy(NewInfor->full, row[3]?row[3]:"NULL");
            strcpy(NewInfor->company, row[4]?row[4]:"NULL");
            strcpy(NewInfor->privation, row[5]?row[5]:"NULL");
            strcpy(NewInfor->extension, row[6]?row[6]:"NULL");
            strcpy(NewInfor->emall, row[7]?row[7]:"NULL");
            
            hash_table_insert(row[i]?row[i]:"NULL", NewInfor);//给每一行的每一列进行hash算法，插入hash表；
        }
    }
}

void hash_table_insert(const char* skey, INFOR* nvalue)//向哈希表中插入元素；
{
    if(hash_table_size >= HASH_TABLE_MAX_SIZE)//当hash表内容个数大与最大hash表容量时提示；
    {
        printf("Out of hash table memory!\n");
        return;
    }
    
    unsigned int pos = hash_table_hash_str(skey) % HASH_TABLE_MAX_SIZE;//计算hash下标；
    HashNode* pHead = hashTable[pos];
    while(pHead)
    {   
        if(skey[0] == '\0')//如果skey为空，则跳出；
        {
            return;
        }
        if(strcmp(pHead->sKey, skey) == 0 && strcmp(pHead->infor->emall, nvalue->emall) == 0)//判断是否为同名同人，邮箱为唯一的；
        {
            printf("%s already exists!\n", skey);
            return;
        }
        pHead = pHead->pNext;
    }
    HashNode* pNewNode = (HashNode*)malloc(sizeof(HashNode));//为hash结构分配空间；
    memset(pNewNode, 0, sizeof(HashNode));
    
    pNewNode->sKey = (char*)malloc(sizeof(char)*(strlen(skey)+1));//为结构体中的sKey分配空间；
    memset(pNewNode->sKey, 0, sizeof(char)*(strlen(skey)+1));
    
    strcpy(pNewNode->sKey, skey);
    pNewNode->infor = nvalue;
    pNewNode->pNext = hashTable[pos];
    hashTable[pos] = pNewNode;
    
    hash_table_size++;
}

HashNode* hn[64] = {0};//存储符合条件的节点的地址；
HashNode** hash_table_lookup(char* skey)//查找哈希表数据；
{

    int i;
    for(i=0; i<strlen(skey); i++)//去掉字符串后的回车符号；
    {
        if(skey[i]=='\n')
        {
            skey[i]='\0';
            break;
        }      
    }
    i = 0;
    memset(hn, 0, sizeof(hn));
    unsigned int pos = hash_table_hash_str(skey) % HASH_TABLE_MAX_SIZE;//计算hash下标；
    if(hashTable[pos])
    {
        HashNode* pHead = hashTable[pos];
        while(pHead)//查找下标相同的所有节点；
        {          
            if(strcmp(skey, pHead->sKey) == 0)
            {
                hn[i++] = pHead;//将匹配的节点地址保存到数组；
            }
            pHead = pHead->pNext;
        }
        if(pHead == NULL)//如果查到链表尾部，返回数组；
        {
            return hn;
        }
    }
    return NULL;
}



