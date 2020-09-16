//client
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
#define MAXDATASIZE 100
#define SERVER_IP "10.4.112.4"
#define DATA  "this is a client message"
#define INTERFAXENAME "ens7"
#define PACKET_LEN 131072
static char packetBuf[67108864];

#define MAX_FLOW_DURATION 150.0
inline static double tv2ts(struct timeval tv) {
	return tv.tv_sec + tv.tv_usec/1000000.0;
}

typedef struct MyMessage{
	int ID;
	char info[256];
}MyMessage,*pMyMessage;
int main(int argc, char* argv[]) {
	int sockfd, recvbytes;
	//char buf[MAXDATASIZE];
	MyMessage recvData;
	struct sockaddr_in serv_addr;

	//if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_RAW)) == -1) {
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket error!");
		exit(1);
	}
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, INTERFAXENAME, sizeof(INTERFAXENAME));
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface))  < 0) {
		perror("SO_BINDTODEVICE failed");
	}
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVPORT);
	serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr))== -1) {
		perror("connect error!");
		exit(1);
	}

	// write(sockfd, DATA, sizeof(DATA));
	memset((void *)&recvData,0,sizeof(MyMessage));
	struct timeval flow_start_time;
	struct timeval cur_time;
	gettimeofday(&flow_start_time, NULL);
	while (1){
		//printf("%f \n",tv2ts(flow_start_time));
		int rval;
		int len = 1024;
		if ((recvbytes = read(sockfd, (void *)packetBuf, sizeof(packetBuf))) < 0){
		//if ((recvbytes = recv(sockfd, (void *)packetBuf,sizeof(packetBuf), 0)) <= 0) {
		//if ((rval = read(sockfd, packetBuf, PACKET_LEN)) < 0) {
			perror("reading stream error!");
			break;
		}

		//gettimeofday(&cur_time, NULL);
		if (recvbytes == 0) break;
		//else printf("%f \n",tv2ts(cur_time) -  tv2ts(flow_start_time));
	}

	/*
	if ((recvbytes = recv(sockfd, (void *)&recvData,sizeof(MyMessage), 0)) == -1) {
		perror("recv error!");
		exit(1);
	}*/
	//buf[recvbytes] = '\0';
	//printf("Received:ID=%d,Info= %s",recvData.ID,recvData.info);
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
	return 0;
}
