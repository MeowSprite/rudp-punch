#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(int argc, char *argv[])
{
    int sock;
    //sendto中使用的对方地址
    struct sockaddr_in toAddr;
    //在recvfrom中使用的对方主机地址
    struct sockaddr_in fromAddr;
    int recvLen;
    unsigned int addrLen;
    char recvBuffer[128];
    sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock < 0)
    {
        printf("创建套接字失败了.\r\n");
        exit(0);
    }
    memset(&fromAddr,0,sizeof(fromAddr));
    fromAddr.sin_family=AF_INET;
    fromAddr.sin_addr.s_addr=htonl(INADDR_ANY);
    fromAddr.sin_port = htons(4000);
    if(bind(sock,(struct sockaddr*)&fromAddr,sizeof(fromAddr))<0)
    {
        printf("bind() 函数使用失败了.\r\n");
        close(sock);
        exit(1);
    }
    while(1){
        addrLen = sizeof(toAddr);
        if((recvLen = recvfrom(sock,recvBuffer,128,0,(struct sockaddr*)&toAddr,&addrLen))<0)
        {
            printf("()recvfrom()函数使用失败了.\r\n");
            close(sock);
            exit(1);
        }
        printf("good\n");
        if(strcmp(recvBuffer,"\x01") == 0)
        {
            printf("yes\n");
        }
        if(sendto(sock,recvBuffer,recvLen,0,(struct sockaddr*)&toAddr,sizeof(toAddr))!=recvLen){
            printf("sendto fail\r\n");
            close(sock);
            exit(0);
        }
        return 0;
    }
}
