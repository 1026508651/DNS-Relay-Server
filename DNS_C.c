/*2022-07 北京邮电大学计算机网络课程设计:DNS中继服务器*/
/*2022-07 BUPT Computer Network Course Design:DNS Relay Server*/
//代码主要设计：ZXHE
//Author:ZXHE
//zhengxunhe@bupt.edu.cn
//zhengxunhe@163.com

//DNS_C.c main part of the program. 
//Include main function ,part of basic datastructure 
//and the main logic
//DNS_C.c 本程序的主要部分
//包含了main函数和基础数据结构的定义以及主要业务逻辑

//DNS超512情况采用TCP 本程序未考虑
//This program has not taken the situation which the size of DNS
//report is larger than 512 Bytes into consideration since this type 
//of DNS request will use TCP protocal instead of UDP
#ifdef _WIN32 /* for Windows Visual Studio */
#include <stdio.h>
#include <stdlib.h>
#include "basic.h"
#include <WinSock.h>
#include <string.h>
#include "lprintf.h"
#include <sys/timeb.h>
#include "getopt.h"//linux和windows不一样的地方
#else /* for Linux */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#endif
#pragma comment(lib, "wsock32.lib")/*Dynamic Lib Import*/
//WinSock IP Address Transformer
//Modify:
//put effective 16-based ip into addr(char-array)
//修改：
//将有效的16进制ip地址按顺序放入addr char数组中
//Effect:
//Transform the original WINSOCKADDR-based ip address in addr into four 16-based ip adresses 
//作用
//将addr数组中原有的WINSOCKADDR格式（整型）的ip地址转化为四位16进制ip地址
//Require
//addr must be WinSockAddr ip address
//要求
//传入的参数addr需为WinSockAddr类型的ip地址参数
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

//自定义消息
//用途：用于作为识别码在Windows系统收到下一个活动消息时
//识别是否为既定有效活动信息（如收到消息/连接断开）
//SELF-DEFINE MESSAGE
//Usage: To be used as an ID to recognize effective message recived by the Windows
//System such as connection and message recieved
#define WM_SOCKET WM_USER + 114
//DEBUG 类型
//0:无调试信息输出
//1:少量调试信息输出，包括时间坐标/序号/客户端IP地址/查找域名
//2:所有调试信息输出，包括1中信息+所有的[TIMEOUT][SEND][STATUS][RECV]信息
//debug type: option to show debug information in three level
//0:least information
//1:ordinary information(time Stamp,series number, client ip address, domination name)
//2:detailed information(information in 1 + Whole[SEND]/[STATUS]/[RECV] information)
static int dbgType = 2;
//Usage: A link table unit designed to save the basic information
//(client ip/port, original ID, send ID and the visit time of this query) of a DNS query
//sent to remote DNS server.
//用途：一个用于存储发送给远程DNS服务器请求的基本信息（客户端地址,原始ID,发送用ID和该链表单元访问次数）的链表单元
typedef struct index {
	//回传地址保存(包括IP和端口)
	//To save the client adress including ip adress and port
	SOCKADDR_IN addSave;
	//原有ID/做头时为有效数据个数
	//original ID of a DNS query/ Act as the counter of query in
	//this link table when being the head of the link table
	int oriID;
	//发送ID,直接截取两字节的内存保存
	//Send Id, cutting from the first two Bytes of recvbuf directly
	char sendID[2];
	//访问次数统计 超过一定次数直接删除防止丢包占用内存
	//visit time counter. If this counter exeeds MINIMAL_VISIT_TIME, the unit will be 
	//deleted from the link table
	int searchTime;
	//指向下一个单元的指针(最后一个单元为NULL)
	//the pointer points to the next unit(The last unit will be set to NULL)
	struct index* next;
}REQ_INDEX;
//DNS Server Address
//DNS服务器地址
SOCKADDR_IN addrSer;
//DNS服务器IP
//DNS Server IP
static char DNSAddRemote[] = "222.172.200.68";
//本地监听IP
//Local IP
static char DNSAddLocal[] = "127.0.0.1";
//默认DNS中继地址存储文件
//Default DNS relay file
static char DNSFile[] = "DNSrelay.txt";
//请求链表头
//Request link table header
REQ_INDEX sendCache[512];
//Timestamp
//时间戳
static time_t epoch;
//The ONLY socket in this programm
//本程序唯一的SOCKET
SOCKET* socketDNS;
//DNS relay information link table header
//DNS中继信息链表表头
dictIndex saveSegment;
//命令行参数，详见usage
//the paras of consle, described in usage
static struct option intopts[] = {
	{ "help",no_argument, NULL, '?' },
	{ "debug",required_argument, NULL, 'd' },
	{ "filename",required_argument, NULL, 'f' },
	{ "ipAddress",	required_argument, NULL, 'i' },
	{ 0, 0, 0, 0 },
};
//the requirement of consle options
//命令行参数的要求
static char *optstring = "?d:f:i:";
//readFile:read the DNSrelay file
//Modify:
//saveSegment
//修改：
//saveSegment
//Effect:
//add link table unit to saveSegment in order to save the DNS relay information 
//作用
//将DNSrelay文件中所有的DNS中继信息读入并以链表形式存入saveSegment中
//Require
//fileName must be an effective file name saved in char array or the program will
//print [ERROR] and shut down
//要求
//传入的参数fileName为可读且符合格式的地址文件的地址或文件名，否则程序报错[ERROR]并自动结束
int readFile(char* fileName);
//connectInit:initialize the connection of DNS relay server(bind port and listening)
//初始化DNS中继服务器的连接（绑定端口和监听）
//Modify:
//sockDNS
//修改：
//sockDNS
//Effect:
//initialize the connection of DNS relay server(bind port and listening),make the
//function WSAAsyncSelect work to listening and catching effective information to
//realize asynchronous message processing
//作用：
//初始化DNS socket连接（绑定端口并监听）同时调用WSAAsyncSelect用于监听和捕捉有效信息
//从而实现异步处理信息
//Require
//sockDNS must be a winsock pointer pointing at an effective winSocket unit.
//add must be an effctive local ip address(mostly 127.0.0.1)
//hWnd must be a HWND handler created with a window.
//type must be CONN_CLI or CONN_SER to point out the type of this socket connection
//要求
//sockDNS需要为一个有效的指向一个winsocket单元的指针
//add需要为一个有效的本地监听地址(通常为127.0.0.1)
//hWnd需要为一个窗口的句柄
//type必须为CONN_CLI或CONN_SER其中一个，用于指明连接类型
int connectInit(SOCKET* sockDNS,char* add,HWND hWnd,int type);
//timeoutDetect:delete those units that are timeout(searchTime is more than MINIMAL_VISIT_TIME)
//超时检测：删去访问次数超过MINIMAL_VISIT_TIME的请求缓存单元
//Modify:
//sendCache
//修改：
//sendCache
//Effect:
//delete those request unit whose visit time is more than MINIMAL_VISIT_TIME
//作用：
//超时检测：删去访问次数超过MINIMAL_VISIT_TIME的请求缓存单元
//Require
//segCache is the series code of the request whose response has been recieved
//要求
//segCache是收到回复的请求所在存储单元的头序号
void timeoutDetect(int segCache);
//DNS Debug: print the debug information with timestamp according to the debugtype.
//DNS Debug: 根据debugtype输出带有时间戳的debug信息
//Modify:
//None
//修改：
//None
//Effect:
//print the debug information with timestamp according to the debugtype.
//作用：
//根据debugtype输出带有时间戳的debug信息
//Require
//format is a stirng just like the first paramater for function printf, debugTy is the debugType of this information.
//the paras after that are just like paras in printf
//要求
//format是格式化输出的字符串,debugTy是该条debug信息对应的debug级别，之后的参数是格式化输出所含有的参数
int DNSdebug(const char *format,const int debugTy, ...);
//windows callback function
//windows回调函数 
//Modify:
//socketDNS,saveSegment,sendCache
//修改：
//socketDNS,saveSegment,sendCache
//Effect:
//Process the recieved message based on different types
//作用：
//根据收到的数据报种类对其进行处理
//Require
//hWnd is the handle of the windo that has recieved the message
//uMsg is the message mentioned in the function WSAAsyncSelect
//wParam is the first paramater and in this function it would be a winsokcet which recieved the message
//lpara is the second paramater and in this function it would be the type of message that need to be processed
//要求
//hWnd为对应的窗口句柄
//uMsg为约定好的发送信息，用于校验该信息是否需要处理
//wParam为第一个参数，在这里储存着收到信息的socket
//lParam为第二个参数，在这里为需要处理的事件类型
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
//urlTrans
//DNS域名转为普通域名
//Modify:
//output offset
//修改：
//output offset
//Effect:
//Transform the DNS url into ordinary url and save it in the output array, return the offset
//作用：
//将DNS域名转为普通域名保存在output中并将偏移量返回
//Require
//savebuf save the whole data recieved from the socket
//offset shows the beginning of the url
//output is the location to save the outcome of transformation
//要求
//savebuf是存储了接受自socket全部信息的字符串
//offset指明了url开始的位置
//output用于存储转换结果，需为char数组
int urlTrans(char* savebuf, int offset, char* output);
//配置命令行行为
//set the consle options
static void config(int argc, char **argv);

int main(int argc, char *argv[]) {
	config(argc, argv);
	readFile(DNSFile);
	memset(sendCache, 0, 512 * sizeof(REQ_INDEX));
	printf(
		"\nDesigned By Zhengxun He"
		"\nCurrent Options : \n"
		"DNS FILE:%s\n"
		"DNS Remote Server:%s\n"
		"DNS Listening IP:%s\n"
		"Debug Type:%d\n"
		"=============================================================\n"
		"                    DNS Server Begin                               \n"
		"-------------------------------------------------------------\n"
		, DNSFile, DNSAddRemote, DNSAddLocal, dbgType);
	/*创建socket活动窗口用于支持异步消息处理*/
	/*create the activity window for socket in order to support asynchronous message processing*/
	char szClassName[] = "MainWClass";
	WNDCLASSEX wndclass;
	wndclass.cbSize = sizeof(wndclass);
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = WindowProc;
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hInstance = NULL;
	wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = szClassName;
	wndclass.hIconSm = NULL;
	RegisterClassEx(&wndclass);
	HWND hWnd = CreateWindowEx(0, szClassName, "WSAAsyncSelect",
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);
	if (hWnd == NULL)
	{
		DNSdebug("[Error]FAIL CREATE WINDOW\n",0);
		return FAIL;
	}
	/*设置远程DNS服务器地址*/
	/*set the address and ip of remote DNS server*/
	addrSer.sin_addr.S_un.S_addr = inet_addr(DNSAddRemote);
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(53); //port DNS端口53
	
	socketDNS = malloc(sizeof(SOCKET));
	if (connectInit(socketDNS, DNSAddLocal, hWnd,CONN_CLI) != SUCCESS) {
		DNSdebug("[Error]FAIL CONNECT DNS\n", 0);
		return FAIL;
	};
	
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		// 转化键盘消息
		TranslateMessage(&msg);
		// 将消息发送到相应的窗口函数
		DispatchMessage(&msg);
	}
	// 当GetMessage返回0时程序结束
	return msg.wParam;
}
int readFile(char* fileName) {
	FILE *fp;
	fp = fopen(fileName, "r");
	if (fp == NULL) {
		DNSdebug("Fail to open file %s!\n",0,fileName);
		exit(0);  //退出程序（结束程序）
	}
	char saveDot;
	char ipSave[10] = { 0 };
	char urlSave[100] = { 0 };
	int i,j;
	int urlLen = 0;
	int tempInt = 0;
	dictIndex* currentInd=&saveSegment;
	/*按存储规则读取*/
	/*read the file based on the format*/
	for (i = 0;!feof(fp); i++) {
		memset(urlSave, 0, 100);
		memset(ipSave, 0, 4);
		currentInd->next = (dictIndex*)malloc(sizeof(dictIndex));
		memset(currentInd->next, 0, sizeof(dictIndex));
		tempInt = 0;
		urlLen = 0;
		for (j = 0; j < 4;j++) {
			fscanf_s(fp, "%d", &ipSave[j]);
			tempInt += ipSave[j];
			fscanf_s(fp, "%c", &saveDot);
		}
		fscanf(fp,"%s", urlSave);
		urlLen = strlen(urlSave);
		currentInd = currentInd->next;
		saveSegment.urlSize++;
		if (tempInt == 0) {//拦截
			currentInd->type = URLTypeNo;
		}
		else {//可以找到
			currentInd->type = URLTypePer;
			currentInd->resource.Class = htons(1);
			currentInd->resource.Type = htons(1);
			currentInd->resource.TTL = htonl(600);//10minutes
			currentInd->resource.RDLENGTH = htons(4);//ip跟在后面
		}
		//hton 正常字序到网络
		//ntoh 网络到正常
		memcpy(currentInd->url, urlSave, urlLen);
		currentInd->urlSize = urlLen;
		memcpy(&(currentInd->ip), ipSave, sizeof(char) * 4);
		currentInd->next = NULL;
	}
	return 0;
}
//A function for lprintf to get the time location from epoch(timestamp)
//lprintf模块的子函数
unsigned int get_ms(void)
{
	struct _timeb tm;

	_ftime64_s(&tm);

	return (unsigned int)(epoch ? (tm.time - epoch) * 1000 + tm.millitm : 0);
}

int DNSdebug(const char *format, const int debugTy, ...)
{
	int n = 0;
	//根据debug级别决定是否调用lprintf函数输出
	//determine whether to use lprintf to print the debug information based on dbgType
	if (debugTy <= dbgType) {
		va_list arg_ptr;
		va_start(arg_ptr, debugTy);
		n = __v_lprintf(format, arg_ptr);
		va_end(arg_ptr);
	}
	return n;
}
int connectInit(SOCKET* sock,char* add,HWND hWnd,int type){
	
	/*初始化动态链接库 只有成功初始化并
	声明版本和回传信息后才能继续使用其他API函数*/
	/*Innitialize the DLL of WinSocket
	this is the preq of using other APIs*/
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	wVersionRequested = MAKEWORD( 1, 1 );
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return FAIL;
	}
	/*版本检查*/
	/*Version Check*/
	if ( LOBYTE( wsaData.wVersion ) != 1 ||HIBYTE( wsaData.wVersion ) != 1 ) {
		WSACleanup( );
		return FAIL;
	}
	/*Build up the socket connection
	According to the requirement,
	it should be built with UDP protacal with SOCK_DGRAM*/
	/*建立socket连接，根据要求使用
	SOCK_DGRAM关键字建立UDP连接*/
	*sock = socket(AF_INET, SOCK_DGRAM,0);
	/*bind the port with this socket*/
	/*为该socket连接绑定端口*/
	/*SELF:N SOCKET:H*/
	/*SELF->SOCKET hton s/l*/
	/*SOCKET->SELF ntoh s/l*/
	//服务器转发连接socket地址
		
	if (type == CONN_CLI) {
		SOCKADDR_IN addrCli;
		addrCli.sin_addr.S_un.S_addr = INADDR_ANY;
		addrCli.sin_family = AF_INET;
		addrCli.sin_port = htons(53);

		//bind the connection between Client and THIS SERVER
		if (bind(*sock, (SOCKADDR*)&addrCli, sizeof(SOCKADDR)) == SOCKET_ERROR)
		{
			DNSdebug("[ERROR]Local Server Listen Fail!\n", 0);//DEBUG_0
			return FAIL;
		}
		listen(*sock, 5);//number of acceptable link:5 
		DNSdebug("[STATUS]Server Port 53 is Listenning \n", 2);//DEBUG_2ND
	}
	else {
		return SUCCESS;
	}
	time(&epoch);

	WSAAsyncSelect(*sock, hWnd, WM_SOCKET, FD_READ | FD_CLOSE );
	
	return SUCCESS;
}
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_SOCKET:
	{
		// 取得有事件发生的套节字句柄
		// get the handle of socket in this window
		SOCKET s = wParam;
		// 查看是否出错
		//check if there is error
		if (WSAGETSELECTERROR(lParam))
		{
			closesocket(s);
			DNSdebug("[ERROR] socket %s:error occurs, error code %d\n",0, s, WSAGetLastError());//报错
			return 0;
		}
		// 处理发生的事件
		switch (WSAGETSELECTEVENT(lParam))
		{
		
			case FD_READ:
			{
				char rcvbuf[4096] = { 0 };
				HEADER *p;
				SOCKADDR_IN tempADD;
				int namelen=sizeof(tempADD);
				int checkRead;
				int lenth=recvfrom(s, rcvbuf, 512, 0,(struct sockaddr*)&tempADD,&namelen);// 全部收下 Recieve all
				if (lenth == -1) {
					checkRead = WSAGetLastError();
					DNSdebug("[ERROR] socket %s:error occurs when recv, error code %d\n", 0, s, checkRead);//报错
				}
				//报头处理
				//processing the header
				int recvbufPtr = 12;//偏移指针
				p = (HEADER *)rcvbuf;
				char biggerOutBuf[2] = { 0 };
				memcpy(biggerOutBuf, (char*)p + 2, 2);
				char endianOutBuf[2] = { 0 };
				endianOutBuf[0] = biggerOutBuf[1];
				endianOutBuf[1] = biggerOutBuf[0];
				memcpy((char*)p + 2, endianOutBuf, 2);
				HEADER* saveHead = malloc(sizeof(HEADER));//暂存正常报头
				memset(saveHead, 0, sizeof(HEADER));
				saveHead->id = ntohs(p->id);
				saveHead->qr = p->qr;
				saveHead->opcode = p->opcode;
				saveHead->aa = p->aa;
				saveHead->tc = p->tc;
				saveHead->rd = p->rd;
				saveHead->ra = p->ra;
				saveHead->z = p->z;
				saveHead->rcode = ntohs(p->rcode);
				saveHead->qdcount = ntohs(p->qdcount);
				saveHead->ancount = ntohs(p->ancount);
				saveHead->nscount = ntohs(p->nscount);
				saveHead->arcount = ntohs(p->arcount);
				memset(biggerOutBuf, 0, sizeof(char) * 2);//恢复被调整的位数
				memcpy(biggerOutBuf, (char*)p + 2, 2);
				memset(endianOutBuf, 0, sizeof(char) * 2);
				endianOutBuf[0] = biggerOutBuf[1];
				endianOutBuf[1] = biggerOutBuf[0];
				memcpy((char*)p + 2, endianOutBuf, 2);
			
				if (saveHead->qr == 1) {//回复
					int i;
					DNSdebug("[RECV]ID%4x Remote Response Recv.\n", 1, saveHead->id);
					//寻找该回应对应的请求
					int length;
					int segCache = saveHead->id % 512;
					int judgeExist = FAIL;
					REQ_INDEX* formerReq = &sendCache[segCache];
					REQ_INDEX* currentReq = sendCache[segCache].next;
					for (i = 0; i < sendCache[segCache].oriID-1; i++) {
						if (rcvbuf[0]==currentReq->sendID[0]&&currentReq->sendID[1]==rcvbuf[1]) {
							formerReq->next = currentReq->next;//将该节点拿出 原有链删除该节点
							judgeExist = SUCCESS;//找到
							break;
						}
						else {
							formerReq = currentReq;
							currentReq = currentReq->next;

						}
					}
				
					if (judgeExist == SUCCESS) {
					
						saveHead->id = currentReq->oriID;
						p->id = htons(saveHead->id);//恢复原有ID
						int check = sendto((*socketDNS), rcvbuf, lenth, 0, &(currentReq->addSave), sizeof(SOCKADDR_IN));//试试先
						if (check < 0) {
							int check2;
							check2 = WSAGetLastError();
							DNSdebug("[ERROR]Response Sending Error: ID %4x ERROR %d\n", 0,saveHead->id, check2);
						}
						else {
							DNSdebug("[SEND]Response of ID %4x has been sent SUCCESSFULLY to Port%6d\n---------------------------------------------------------------------\n", 1, saveHead->id,currentReq->addSave.sin_port);
							sendCache[segCache].oriID--;//拿出来长度减小
							free(currentReq);//发送回传成功，则释放该节点

						}
					}//超时处理
					else {
						DNSdebug("[TIMEOUT]Query of response ID %4x has been timeout\n", 2, saveHead->id);
					}
					timeoutDetect(segCache);
				}
				else {//询问
				//读请求报文
						if (saveHead->rcode != 0) {
							break;//rcode 询问必须置零 回复不一定为0
						}
						char **nameBufQu = (char**)malloc(sizeof(char*)* saveHead->qdcount);//QA段域名缓冲
						int *nameBufQulen=(int *)malloc(sizeof(int)*saveHead->qdcount);//长度记录
						int i, j, count = 0,total;
						memset(nameBufQulen, 0, saveHead->qdcount);
						for (i = 0; i < saveHead->qdcount; i++) {
							nameBufQu[i] = (char*)malloc(sizeof(char) * 200);
						}
						int judgeTrans = 0;
						for (i = 0; i < saveHead->qdcount; i++) {
							memset(nameBufQu[i], 0, 200);
							//读域名
							int originPtr = recvbufPtr;
							recvbufPtr=urlTrans(rcvbuf, recvbufPtr, nameBufQu[i]);
							//读Type和Class
							nameBufQulen[i] = recvbufPtr - 1 - originPtr;
							QSUnit* qs = (QSUnit*)malloc(sizeof(QSUnit));
						
							memcpy(qs, rcvbuf + recvbufPtr, sizeof(QSUnit));
							qs->QCLASS = ntohs(qs->QCLASS);
							qs->QTYPE = ntohs(qs->QTYPE);
							recvbufPtr += sizeof(QSUnit);
							if (qs->QCLASS != 1) {
								judgeTrans = 1;
							}
						}
						DNSdebug("---------------------------------------------------------------------\n[RECV]ID%4x Query Recv from Port %6d .Asking for %2d IPs,the first is %s\n", 1, saveHead->id,tempADD.sin_port,saveHead->qdcount,nameBufQu[0]);
						int judgeTransed = 0;
						if (judgeTrans == 0) {
							//全部类别一致 可以查表
							for (i = 0; i < saveHead->qdcount; i++){
								dictIndex* currenInd=saveSegment.next;
								for (j = 0; j < saveSegment.urlSize; j++) {
									if (currenInd->urlSize == (nameBufQulen[i]-1) && strcmp(currenInd->url, nameBufQu[i]) == 0) {
										memset(endianOutBuf, 0, sizeof(char) * 2);
										memset(biggerOutBuf, 0, sizeof(char) * 2);//再次调整（需要换位）
										memcpy(biggerOutBuf, (char*)p + 2, 2);
										endianOutBuf[0] = biggerOutBuf[1];
										endianOutBuf[1] = biggerOutBuf[0];
										memcpy((char*)p + 2, endianOutBuf, 2);
										if (currenInd->type == URLTypeNo) {
											p->rcode = 3;
										}
										p->qr = 1;
										p->ra = 1;
										memset(biggerOutBuf, 0, sizeof(char) * 2);//恢复被调整的位数
										memcpy(biggerOutBuf, (char*)p + 2, 2);
										memset(endianOutBuf, 0, sizeof(char) * 2);
										endianOutBuf[0] = biggerOutBuf[1];
										endianOutBuf[1] = biggerOutBuf[0];
										memcpy((char*)p + 2, endianOutBuf, 2);
										if (currenInd->type == URLTypeNo) {
											sendto(s, rcvbuf, lenth, 0, &tempADD, sizeof(tempADD));//拦截
											DNSdebug("[SEND]ID%4x Query Response locally.%s has been intercepted\n---------------------------------------------------------------------\n", 1, saveHead->id, nameBufQu[0]);
										}
										else if (currenInd->type == URLTypePer) {
											p->ancount = htons(1);
											rcvbuf[recvbufPtr] = 192;//压缩地址
											rcvbuf[recvbufPtr + 1] = 12;
											recvbufPtr += 2;
											memcpy(rcvbuf+recvbufPtr,&currenInd->resource,sizeof(RRUnit));
											recvbufPtr += (sizeof(RRUnit)-2);//sizeofRRunit自动化会对齐
											memcpy(rcvbuf + recvbufPtr, &(currenInd->ip), sizeof(char) * 4);
											recvbufPtr += sizeof(char)*4;
											sendto(s, rcvbuf, recvbufPtr, 0, &tempADD, sizeof(tempADD));
											DNSdebug("[SEND]ID%4x Query Response locally.The ip of %s is %d.%d.%d.%d\n---------------------------------------------------------------------\n", 1, saveHead->id, nameBufQu[0],currenInd->ip[0], currenInd->ip[1], currenInd->ip[2], currenInd->ip[3]);
										}
										judgeTransed = 1;//有效
										break;
									}
									else {
										judgeTransed = 2;//无效
										currenInd = currenInd->next;
									}
								}
							}

						}
						if(judgeTransed==2/*查表查不到*/||judgeTrans!=0/*类型不一致直接转发*/) {
							//不能查表 直接转发
							int segCache = (saveHead->id) % 512;
							REQ_INDEX* currentIndex=sendCache[segCache].next;
							REQ_INDEX* formerIndex=&sendCache[segCache];
							for (i = 0; i < sendCache[segCache].oriID-1/*防止currentIndex变成NULL*/; i++) {
								currentIndex = currentIndex->next;
								formerIndex = formerIndex->next;
							}
							currentIndex = (REQ_INDEX*)malloc(sizeof(REQ_INDEX));
							formerIndex->next = currentIndex;
							sendCache[segCache].oriID++;//长度扩张
							memset(currentIndex, 0, sizeof(REQ_INDEX));
						
							currentIndex->next = NULL;
							currentIndex->oriID = saveHead->id;
							currentIndex->searchTime = 0;
							currentIndex->addSave = tempADD;
							char tempSendID[2] = { 0 };
							short temp = segCache + sendCache[segCache].oriID * 512;
							memcpy(tempSendID, &temp, 2);
							currentIndex->sendID[0] = tempSendID[1];
							currentIndex->sendID[1] = tempSendID[0];
							rcvbuf[0] = currentIndex->sendID[0];
							rcvbuf[1] = currentIndex->sendID[1];
							int check1 = 0;
							DNSdebug("[SEND]ID%4x Query for %s cannot find locally,Send to Remote DNS Server\n", 1, p->id,nameBufQu[0]);
							check1=sendto(*socketDNS, rcvbuf, recvbufPtr, 0,&addrSer,sizeof(addrSer));//转发
							if (check1 < 0) {
								int check2;
								check2 = WSAGetLastError();
								DNSdebug("[ERROR]ID:%4x SEND ERROR: %d\n", 0, saveHead->id,check2);
							}
						}

					
				}
			}
			break;
			case FD_CLOSE:
			{
				closesocket(s);
				DNSdebug("[CLOSE] sock %d close socket\n", s);
			}
			break;
		}
	}
	return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}

	return DefWindowProc(hWnd, uMsg, wParam, lParam);
	
}
int urlTrans(char* savebuf, int offset, char* output) {
	int count = 0;
	int total = 0;
	unsigned char lenQ;

	lenQ = savebuf[offset++];
	while (lenQ != 0)
	{
		if (count != lenQ) {

			output[total++] = savebuf[offset++];
			count++;
		}
		else {

			lenQ = savebuf[offset++];
			if (lenQ != 0)output[total++] = '.';
			count = 0;
		}
	}
	output[total] = 0;
	return offset;
}

void timeoutDetect(int segCache) {
	REQ_INDEX* formerReq = &sendCache[segCache];
	REQ_INDEX* currentReq = sendCache[segCache].next;
	int i = 0;
	for (i = 0; i < sendCache[segCache].oriID - 1; i++) {
		if (currentReq->searchTime > 50) {
			formerReq->next = currentReq->next;//将该节点拿出 原有链删除该节点
			DNSdebug("[TIMEOUT]Query oriID:%4x REQ is Time Out, REMOVE!\n", 2, currentReq->oriID);
			free(currentReq);
			currentReq = formerReq->next;
		}
		else {
			currentReq->searchTime++;
			formerReq = currentReq;
			currentReq = currentReq->next;
		}
	}
}
static void config(int argc, char **argv)
{
	int   i, opt;
	if (argc < 2) {
	usage:
		printf("\nUsage:\n  DNS_C <options> <filename/serverIp>\n");
		printf(
			"\nOptions : \n"
			"    -?, --help : print this\n"
			"    -d, --debug <debugMask#>: debug mask:0-ordinary, 1-basic,2-detail\n"
			"    -f, --filename <filename>  : using assigned file as DNS relay file\n"
			"    -i, --ipAddress <ip> : using assigned ip server as remote DNS server\n"
			"\n"
			"i.e.\n"
			"    DNS_C -d 1 -f dnsrelay.txt\n"
			"    DNS_C -d 0 -i 192.168.1.1\n"
			"\n");
		exit(0);
	}
	
	
	while ((opt = getopt_long(argc, argv, optstring, intopts, NULL)) != -1) {
		switch (opt) {
		case '?':
			goto usage;

		case 'd':
			dbgType = atoi(optarg);
			break;

		case 'f':
			strcpy(DNSFile, optarg);
			break;

		case 'i':
			strcpy(DNSAddRemote, optarg);
			break;

		default:
			printf("ERROR: Unsupported option\n");
			goto usage;
		}
	}


}