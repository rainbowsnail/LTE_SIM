//server
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#define SERVPORT 3333
#define BACKLOG 10
#define MAXSIZE 10240
#define PACKET_LEN 4 //131072
#define MAX_FLOW_DURATION 150.0
static char packetBuf[67108864];

#define INTERFAXENAME "veth7-6"

typedef struct MyMessage{
    int ID;
    char info[256];
}MyMessage,*pMyMessage;

inline static double tv2ts(struct timeval tv) {
	return tv.tv_sec + tv.tv_usec/1000000.0;
}

int main() {
	int sockfd, client_fd;
	struct sockaddr_in my_addr;
	struct sockaddr_in remote_addr;
	//创建套接字
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket create failed!");
		exit(1);
	}
	struct ifreq interface;
    strncpy(interface.ifr_ifrn.ifrn_name, INTERFAXENAME, sizeof(INTERFAXENAME));
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) {
           perror("SO_BINDTODEVICE failed");
    }
    int on = 1;
    if((setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)     {
        perror("setsockopt failed");
        //exit(EXIT_FAILURE);
    }
    //int n;
	//unsigned int m = sizeof(n);
    //getsockopt(fdsocket,SOL_SOCKET,SO_RCVBUF,(void *)&n, &m);

	//绑定端口地址
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVPORT);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(my_addr.sin_zero), 8);
	if (bind(sockfd, (struct sockaddr*) &my_addr, sizeof(struct sockaddr))== -1) {
		perror("bind error!");
		exit(1);
	}
	//监听端口
	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen error");
		exit(1);
	}
	//while (1) {
		//int sin_size = sizeof(struct sockaddr_in);
		socklen_t sin_size = sizeof(struct sockaddr_in);
		if ((client_fd = accept(sockfd,(struct sockaddr*) &remote_addr,&sin_size)) == -1){
			perror("accept error!");
			//continue;
		}
		// printf("Received a connection from %s\n", (char*)inet_ntoa(remote_addr.sin_addr));
 
		//子进程段
		//if (!fork()){
			struct timeval flow_start_time;
			struct timeval cur_time;
			gettimeofday(&flow_start_time, NULL);
			ssize_t nleft = sizeof(packetBuf);//PACKET_LEN;
			ssize_t nwritten;
			const char *bufp = (const char*)packetBuf;
			char errbuf[256];

			while (nleft > 0) {
				// if ((nwritten = write(client_fd, bufp, nleft)) <= 0) {
				if(nwritten = send(client_fd,(void*)bufp,PACKET_LEN,0) <= 0) {
				//if(send(client_fd,(void*)bufp,sizeof(packetBuf),0) == -1){
					if (errno == EINTR) {
						perror("Write interrupted!");
						//logVerbose("Write interrupted.");
						//n -= nleft;
						break;
					}
					else {
						perror("Write error!");
						//logError("Write error(%s).", strerrorV(errno, errbuf));
						//n = -1;
						break;
					}
				}
				nleft -= nwritten;
				bufp += nwritten;
				gettimeofday(&cur_time, NULL);
				if (tv2ts(cur_time) -  tv2ts(flow_start_time) > MAX_FLOW_DURATION) break;
				//if ( cur_time.tv_sec - flow_start_time.tv_sec + double(cur_time.tv_usec - flow_start_time.tv_usec)/1000000 > MAX_FLOW_DURATION ){
				//	break;
				//}
			}
			
			/*
			//接受client发送的请示信息
			int rval;
			char buf[MAXSIZE];
			if ((rval = read(client_fd, buf, MAXSIZE)) < 0) {
				perror("reading stream error!");
				continue;
			}
			printf("%s\n", buf);
			//向client发送信息
			//char* msg = "Hello,Mr hqlong, you are connected!\n";
			MyMessage data;
			memset((void *)&data,0,sizeof(MyMessage));
			data.ID=123;
			strcpy(data.info,"This message come from ServSocket!");
			if(send(client_fd,(void*)&data,sizeof(MyMessage),0) == -1){
				perror("send error!");
			}
			*/
			shutdown(client_fd, SHUT_RDWR);
			close(client_fd);
			//exit(0);
		//}
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
	//}
	return 0;
}
