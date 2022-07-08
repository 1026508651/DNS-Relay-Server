/*2022-07 北京邮电大学计算机网络课程设计:DNS中继服务器*/
/*2022-07 BUPT Computer Network Course Design:DNS Relay Server*/
//代码主要设计：ZXHE
//Author:ZXHE
//basic.h some basic constants and datastructures used in DNS_C.c
//basic.h 一些在DNS_C.c中用到的基础常量和数据结构
#define getopt_long getopt_int
#define stricmp _stricmp
#define HEAD_Q 0
#define HEAD_R 1
#define DEFAULT_SIZE 13
#define SUCCESS 0



#define FAIL -1
#define COUNTOFFSET 0
#define DEBUG_NO 0
#define DEBUG_1ST 1
#define DEBUG_2ND 2
#define CONN_SER 1
#define CONN_CLI 2
#define TMAX 50
#define URLTypeNo 0
#define URLTypePer 1
#define MINIMAL_VISIT_TIME 50
unsigned int get_ms(void);
typedef struct HEADER {
    unsigned id: 16;    /* query identification number */
    unsigned rcode: 4;  /* response code */
	unsigned z : 3;      /* unused bits, must be ZERO */
	unsigned ra : 1;     /* recursion available */
	unsigned rd : 1;     /* recursion desired */
	unsigned tc : 1;     /* truncated message */
	unsigned aa : 1;     /* authoritive answer */
	unsigned opcode : 4; /* purpose of message */
	unsigned qr : 1;     /* response flag */
    unsigned short  qdcount;       /* number of question entries */
    unsigned short  ancount;       /* number of answer entries */
    unsigned short  nscount;       /* number of authority entries */
    unsigned short  arcount;       /* number of resource entries */
}HEADER;
typedef struct QSUnit {
	unsigned QTYPE:16;
	unsigned QCLASS :16;
}QSUnit;

typedef struct RRUnit {
	unsigned Type : 16;
	unsigned Class : 16;
	unsigned TTL : 32;
	unsigned RDLENGTH : 16;
}RRUnit;

typedef struct dictIndex {
	char url[100]; //存储url 
	int type; //url种类：0：无效地址 1：有效可返回地址
	int urlSize;//url长度
	RRUnit resource;//对应的资源记录
	char ip[4];//对应的ip地址
	struct dictIndex*next;
}dictIndex;
