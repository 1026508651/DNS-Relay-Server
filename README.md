# DNS-Relay-Server

### @ZXHE

#### Introduction

​      Based on winsocket, this project imitated the DNS localhost server in the windows operation system, and will be developed to satisfy the requirement of Linux(Not yet).

#### Functions

​      Basic Functions: Malicious Domain Filtering,Local Domain Lookup,Remote Domain Lookup. Manually setting own DNS remote server IP and local domain name file.

​      Advanced Function: Asynchronous multi-threaded queries(Based on WSAAsyncSelect)

#### Deployment

​   language: C

​	  compiler: gcc

​	  OS:windows10

​      IDE:VS2017

​	  ATTENTION: 

​		1.Deploy before changing all the DNS address in windows10 Network into 127.0.0.1.

​		2.Usage is listed in the program.

#### Structure

├── README.md

├── DNS_C.c //main file

├── DNS_C.rc//resource file

├── DNS_C.vcxproj //project file

├── DNS_C.vcxprk.filters //project file

├── DNS_C.vcxproj.user//project file

├── DNSrelay.txt //local domain name table

├──getopt.c//Linux getopt.c Lib

├──getopt.c//header of Linux getopt.c Lib

├──lprintf.c//a lib function to print the debug information with time coordination

├──lprintf.c//header of lprintf.c, including lprintf and v_lprintf

├──Debug// generation files from VS2017 debug type

├──Release// generation files from VS2017 release type


#### Usage

		DNS_C <options> <filename/serverIp>
		
Options : 
			   -?, --help : print this
	
			   -d, --debug <debugMask#>: debug mask:0-ordinary, 1-basic,2-detail
	
			   -f, --filename <filename>  : using assigned file as DNS relay file
	
			   -i, --ipAddress <ip> : using assigned ip server as remote DNS server
	
			"i.e.
	
			    DNS_C -d 1 -f dnsrelay.txt
	
			    DNS_C -d 0 -i 192.168.1.1
	

#### Reference

1. getopt.c is a library of linux in order to get the options from consle.
2. lprintf.c is a library function in order to print debug information with the timestamp. 
