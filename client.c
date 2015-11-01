#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "rudp_api.h"
#include "event.h"
#include "file_data.h"

enum status{FILE_SEND_STATUS,FILE_RECV_STATUS, CHAT_STATUS};

struct UdpClient{
    struct sockaddr_in *server;
    struct sockaddr_in *friend;
    rudp_socket_t rsocket;
    char pool_id[5];
    int status;
};

struct fileBox{
    struct fileBox* Next;
    int fileopen;    /* True if file is open */
    int fd;    /* File descriptor */
    int fileID;
    char name[FN_FILENAMELENGTH+1]; /* Name of file */
    long fileSize;
    long recvedSize;
    int recvPercent;
};


enum fileQueueStatus{INIT, READY, SENDING, END};
struct fileSendQueue{
    struct fileSendQueue *Next;
    struct UdpClient* arg;
    char file_name[FN_FILENAMELENGTH+1];
    int fd;
    int fileID;
    int fileStatus;
};

int ClientStatus = CHAT_STATUS;
struct fileBox* fileBoxHead;
struct fileSendQueue* fileQueueHead=NULL;

int filesender(int file, void *arg);
void delete_filesend(struct fileSendQueue* filesend);

int connect_to_server(struct UdpClient *clientSession)
{
    int socketfd;
    int servlen, n;
    int err = 0;
    struct sockaddr_in address;
    struct sockaddr_in *serverAddress;
    serverAddress = clientSession->server;
    socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(socketfd < 0){
        fprintf(stderr,"create server socket error");
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(0);

    if(bind(socketfd, (struct sockaddr *)&address, sizeof(address))<0){
        fprintf(stderr,"bind local socket error");
        err = -1;
        goto over;
    }

    /* request to server */
    char buf[30];
    strcpy(buf, "\x01");
    servlen=sizeof(*serverAddress);
    sendto(socketfd, buf, strlen(buf), 0, (struct sockaddr *)serverAddress, (socklen_t)servlen);
    n = recvfrom(socketfd, buf, 30, 0, 0, 0);
    buf[n]='\0';
    if(strcmp(buf, "\x02") != 0)
    {
        printf("connect to server fail 02\n");
        err = -1;
        goto over;
    }

    printf("connect to server success\n");
    /* request pool resource */
    strcpy(buf, "\x03");
    strcat(buf, clientSession->pool_id);
    sendto(socketfd, buf, strlen(buf), 0, (struct sockaddr *)serverAddress, (socklen_t)servlen);
    n = recvfrom(socketfd, buf, 30, 0, 0, 0);
    if(buf[0] != '\x04' || strcmp(buf+1, clientSession->pool_id) != 0){
        printf("connect to server fail 04\n");
        err = -1;
        goto over;
    }
    printf("connect to pool success\n");
    printf("wait for point\n");
    memset(buf,0,30);
    int count = 0;
    while(recvfrom(socketfd, buf, 30, 0, 0, 0)){
        if(buf[0] == '\x05'){
            break;
        }
        if(count > 3){
            printf("recv friend point fail 05\n");
            err = -1;
            goto over;
        }
    }
    unsigned int pointAddr = *(unsigned int*)(buf + 1);
    printf("%u\n", pointAddr);
    struct in_addr cPAddr;
    cPAddr.s_addr = pointAddr;
    printf("%s\n", inet_ntoa(cPAddr));
    char pointPort[10];
    strcpy(pointPort, buf+5);
    printf("%s\n", pointPort);
    struct sockaddr_in *point = malloc(sizeof(struct sockaddr_in));
    point->sin_family = AF_INET;
    point->sin_port = htons(atoi(pointPort));
    point->sin_addr.s_addr = pointAddr;
    clientSession->friend = point;
    //strcpy(buf, "hello!");
    //sendto(socketfd, buf, strlen(buf), 0, (struct sockaddr *)point, (socklen_t)sizeof(*point));
    //n = recvfrom(socketfd, buf, 30, 0, 0, 0);
    //printf("%s\n", buf);
    return socketfd;
over:
    close(socketfd);
    return err;
}

int stop_receive_file(rudp_socket_t rsocket, struct sockaddr_in *remote, int fileID){
    char buf[10];
    buf[0] = fileID;
    strcpy(buf+1, "-t");
    rudp_sendto(rsocket, buf, strlen(buf), remote);
    return 0;
}

int receiver_handle(rudp_socket_t rsocket, struct sockaddr_in *remote, char *buf, int len) {
    if(ClientStatus == CHAT_STATUS)
    {
        if(buf[0] == '-'){
            printf("command status\n");
            switch(buf[1]){
                case 'f':
                printf("start receive file...\n");
                ClientStatus = FILE_RECV_STATUS;
                break;
                default:
                printf("unknown status, ignore it\n");
            }
        }
        else{
            printf(">>>%s\n", buf);
        }
    }
    else if(ClientStatus == FILE_RECV_STATUS){
        /* recive the file */
        struct file_node *fnode = (struct file_node *)buf;
        struct fileBox* filebox = NULL;
        int namelen;
        int i;
        if(len < FN_MINLEN){
            fprintf(stderr, "file_recv: Too short packet (%d bytes)\n", len);
            return 0;
        }
        int typeID = ntohl(fnode->node_type);
        switch (typeID) {
            case FN_TYPE_BEGIN:
            printf("Receiving\n");
            namelen = len - FN_FILENAME_POS; //the first byte is fileID;
            if (namelen > FN_FILENAMELENGTH)
                namelen = FN_FILENAMELENGTH;
            filebox = malloc(sizeof(struct fileBox));
            strncpy(filebox->name, fnode->file_data.fileinfo.filename, namelen);
            filebox->name[namelen] = '\0';
            for (i = 0; i < namelen; i++) {
                char c = filebox->name[i];
                if (!(isalnum(c) || c == '.' || c == '_' || c == '-')) {
                    fprintf(stderr, "vs_recv: Illegal file name: %s\n", filebox->name);
                    //rudp_close(rsocket);
                    // here cancel file transfering
                    stop_receive_file(rsocket, remote, fnode->file_data.fileinfo.fileID);
                    return 0;
                }
            }
            if((filebox->fd = creat(filebox->name, 0666)) < 0){
                fprintf(stderr, "connot create the file: %s\n",filebox->name);
            }
            filebox->fileopen = 1;
            filebox->fileID = fnode->file_data.fileinfo.fileID;
            filebox->fileSize = fnode->file_data.fileinfo.fileSize;
            filebox->recvedSize = 0;
            filebox->recvPercent = 0;
            filebox->Next = fileBoxHead;
            fileBoxHead = filebox;
            break;
            case FN_TYPE_END:
            printf("\n");
            printf("Receive over\n");
            struct fileBox* fileboxScan = fileBoxHead;

            // if the first filebox is the curfilebox
            if(fileBoxHead == NULL)
            {
                printf("there is no file box exists!\n");
                return 0;
            }
            else if(fileBoxHead->fileID==fnode->file_data.fileinfo.fileID)
            {
                filebox = fileBoxHead;
                fileBoxHead = fileBoxHead->Next;
            }
            while(fileboxScan->Next!=NULL && filebox==NULL)
            {
                if(fileboxScan->Next->fileID == fnode->file_data.fileinfo.fileID){
                    filebox = fileboxScan->Next;
                    fileboxScan->Next = filebox->Next;  //delete current file box
                    break;
                }
                fileboxScan=fileboxScan->Next;
            }
            if(filebox == NULL){
                fprintf(stderr, "cannot find the file box\n");
                return 0;
            }
            if(filebox->fileopen){
                close(filebox->fd);
                filebox->fileopen = 0;
            }
            free(filebox);
            // if there is no filebox exists
            if(fileBoxHead == NULL)
                ClientStatus = CHAT_STATUS;
            break;
            default:
            /* receive data */
            if(typeID > FN_TYPE_END){ //fileID
                len -= sizeof(fnode->node_type);
                //printf("len: %d\n", len);
                //printf("fileID: %d\n", typeID);
                filebox = fileBoxHead;
                for(;filebox->Next!=NULL && filebox->fileID != typeID; filebox=filebox->Next);
                if(filebox == NULL){
                    stop_receive_file(rsocket, remote, typeID);
                    fprintf(stderr, "cannot find the file box\n");
                }
                if(filebox->fileopen) {
                    if ((write(filebox->fd, fnode->file_data.data, len)) < 0) {
                        fprintf(stderr, "cannot write the file: %s\n",filebox->name);
                        // here cancel file transfering
                        stop_receive_file(rsocket, remote, typeID);
                        return 0;
                    }
                }
                //printf("allready recv %ld, recv %d\n",filebox->recvedSize, len);
                int newPercent = (filebox->recvedSize + len)*100/filebox->fileSize-filebox->recvPercent;
                filebox->recvPercent += newPercent;
                //printf("newrecv:%d\n", newPercent);
                for(;newPercent > 0;newPercent--)
                {
                    printf(">");
                    fflush(stdout) ;
                }

                filebox->recvedSize += len;
            }
            else
                printf("file_recv: wrong type, ignore\n");
        }
    }
    else if(ClientStatus == FILE_SEND_STATUS){
        printf(">>>%d:%s\n", buf[0], buf+1);
        int fileID = buf[0];
        struct fileSendQueue *filesend = fileQueueHead;
        for(;filesend != NULL && filesend->fileID != fileID;filesend = filesend->Next);
        if(filesend == NULL){
            fprintf(stderr,"filesender: No this file send! stop fail, ignore\n");
            //event_fd_delete_fd(filesender, arg, file);
            return 0;
        }
        event_fd_delete_fd(filesender, filesend->arg, filesend->fd);
        delete_filesend(filesend);
        if(fileQueueHead == NULL)
            ClientStatus = CHAT_STATUS;
    }
    return 0;
}

int eventhandler(rudp_socket_t rsocket, rudp_event_t event, struct sockaddr_in *remote) {
    switch (event) {
        case RUDP_EVENT_TIMEOUT:
            printf("socket time out\n");
            break;
        case RUDP_EVENT_CLOSED:
            printf("prematurely closed communication\n");
            break;
    }
    return 0;
}

int sendMsg(struct UdpClient* pointSession){
    char buf[] = "hello rudp";
    int buflen = strlen(buf);
    rudp_sendto(pointSession->rsocket, buf, buflen, pointSession->friend);
    return 0;
}

void delete_filesend(struct fileSendQueue* filesend)
{
    struct fileSendQueue* fileSendScan = fileQueueHead;
    if(fileQueueHead->fileID == filesend->fileID){
        fileQueueHead = filesend->Next;
    }
    else{
        while(fileSendScan->Next!=NULL)
        {
            if(fileSendScan->Next->fileID == filesend->fileID){
                fileSendScan->Next = filesend->Next;
                break;
            }
        }
    }
    free(filesend);

}

int filesender(int file, void *arg) {
    struct UdpClient* pointSession =   (struct UdpClient*) arg;
    int bytes;
    struct file_node fnode;
    int nodelen;
    struct fileSendQueue *fileSend = fileQueueHead;

    for(;fileSend != NULL && fileSend->fd != file;fileSend = fileSend->Next);
    if(fileSend == NULL){
        fprintf(stderr,"filesender: sendQueue Lost\n");
        event_fd_delete_fd(filesender, arg, file);
        return 0;
    }

    rudp_socket_t rsock = pointSession->rsocket;
    bytes = read(file, &fnode.file_data.data,FN_MAXDATA);

    if (bytes < 0) {
        perror("filesender: read");
        delete_filesend(fileSend);
        event_fd_delete_fd(filesender, arg, file);
        close(file);
    }
    else if(bytes == 0){
        fnode.node_type = htonl(FN_TYPE_END);
        fnode.file_data.fileinfo.fileID = fileSend->fileID;
        nodelen = FN_END_LENGTH;
        printf("send complete! bytes = 0\n");
        if (rudp_sendto(rsock, (char *) &fnode, nodelen, pointSession->friend) < 0) {
            fprintf(stderr,"rudp_sender: send failure\n");
        }
        delete_filesend(fileSend);
        event_fd_delete_fd(filesender, arg, file);
        close(file);
        if(fileQueueHead == NULL)
            ClientStatus = CHAT_STATUS;
    }
    else if (bytes < FN_MAXDATA) {
        #ifdef debug
        printf("send fileID:%d fileName:%s\n", fileSend->fileID, fileSend->file_name);
        #endif
        fnode.node_type = htonl(fileSend->fileID);
        nodelen = sizeof(fnode.node_type) + bytes;
        if (rudp_sendto(rsock, (char *) &fnode, nodelen, pointSession->friend) < 0) {
            fprintf(stderr,"rudp_sender: send failure\n");
            //event_fd_delete(filesender, arg);
            close(file);
        }
        fnode.node_type = htonl(FN_TYPE_END);
        fnode.file_data.fileinfo.fileID = fileSend->fileID;
        //fnode.file_data.fileinfo.fileSize = fileSend->fileSize;
        nodelen = FN_END_LENGTH;
        printf("send complete! bytes < FN_MAXDATA\n");
        if (rudp_sendto(rsock, (char *) &fnode, nodelen, pointSession->friend) < 0) {
            fprintf(stderr,"rudp_sender: send failure\n");
        }
        delete_filesend(fileSend);
        event_fd_delete_fd(filesender, arg, file);
        close(file);
        if(fileQueueHead == NULL)
            ClientStatus = CHAT_STATUS;
    }
    else {
        #ifdef debug
        printf("send fileID:%d fileName:%s\n", fileSend->fileID, fileSend->file_name);
        #endif
        fnode.node_type = htonl(fileSend->fileID);
        nodelen = sizeof(fnode.node_type) + bytes;
        if (rudp_sendto(rsock, (char *) &fnode, nodelen, pointSession->friend) < 0) {
            fprintf(stderr,"rudp_sender: send failure\n");
            event_fd_delete_fd(filesender, arg, file);
            delete_filesend(fileSend);
            close(file);
        }
    }
    return 0;
}

long get_file_size(char* filename)
{
    struct stat statbuf;
    stat(filename,&statbuf);
    long size=statbuf.st_size;
    return size;
}

int send_file(char *filename, struct UdpClient* pointSession)
{
    int file;
    struct file_node filenode;
    char *filename1 = filename;
    int namelen;
    int nodelen;
    rudp_socket_t rsock = pointSession->rsocket;
    printf("%s\n", filename);
    if ((file = open(filename, O_RDONLY)) < 0) {
      fprintf(stderr,"open: error! %s\n", filename);
      return -1;
    }

    /* filling filenode-BEGIN */
    long fileSize = get_file_size(filename);
    filenode.node_type = htonl(FN_TYPE_BEGIN);
    filenode.file_data.fileinfo.fileSize = fileSize;
    if (strrchr(filename1, '/'))
        filename1 = strrchr(filename1, '/') + 1;
    namelen = strlen(filename1) < FN_FILENAMELENGTH  ? strlen(filename1) : FN_FILENAMELENGTH;
    strncpy(filenode.file_data.fileinfo.filename, filename1, namelen);
    nodelen = FN_FILENAME_POS + namelen;

    /* add filesend to the fileSendQueue */
    struct fileSendQueue* fileSend = malloc(sizeof(struct fileSendQueue));
    strcpy(fileSend->file_name, filenode.file_data.fileinfo.filename);
    fileSend->fileStatus = READY;
    fileSend->fd = file;
    fileSend->arg = pointSession;
    fileSend->fileID = file + FN_TYPE_END; //generate a unique fileID from fd & TYPE_END;
    filenode.file_data.fileinfo.fileID = fileSend->fileID;
    fileSend->Next = fileQueueHead;
    fileQueueHead = fileSend;

    /* send the first file_node to the point */
    if (rudp_sendto(rsock, (char *) &filenode, nodelen, pointSession->friend) < 0) {
        fprintf(stderr,"rudp_sender: send failure\n");
        delete_filesend(fileSend);
        close(file);
        return -1;
    }
    //printf("%d\n", file);
    fileSend->fileStatus = SENDING;
    event_fd(file, filesender, pointSession, "filesender");
    return 0;
}

int transfer_file(char (*fileName)[FN_FILENAMELENGTH], int filenum, struct UdpClient *pointSession){
    char buf[]="-f";
    size_t i;
    rudp_sendto(pointSession->rsocket, buf, strlen(buf), pointSession->friend);
    ClientStatus = FILE_SEND_STATUS;
    for (i = 0; i < filenum; i++) {
        //printf("%s\n", fileName[0]);
        send_file(fileName[i], pointSession);
    }
    return 0;
}

int io_handle(int file, void *arg) {
    struct UdpClient* pointSession = arg;
    char buf[2 * FN_FILENAMELENGTH];
    fgets(buf, 2 * FN_FILENAMELENGTH, stdin);
    int buflen = strlen(buf);
    //printf("%d", buflen);
    if(buf[buflen-1] == '\n'){
        //printf("delete return\n");
        buf[buflen-1]='\0';
    }
    if(buf[0] == '-'){
        if(buflen<4)
        {
            printf("!!!please input the right command!!!\n");
            return 0;
        }
        char fileName[5][FN_FILENAMELENGTH];
        char *nameBlock, *prenameBlock;
        switch(buf[1]){
            case 'f':
            /* transfer file command */
            // need deal with fileName range in 0 ~ FN_FILENAMELENGTH
            prenameBlock = buf + buflen - 1;
            int fileNum=0;
            while(nameBlock = strrchr(buf+2, ' ')){
                if(nameBlock != prenameBlock - 1 && nameBlock != prenameBlock){
                    if(fileNum >= 5){
                        printf("too many files input, ignored\n");
                        break;
                    }
                    strcpy(fileName[fileNum++], nameBlock+1);
                }
                prenameBlock = nameBlock;
                *nameBlock='\0';
            }
            #ifdef debug
            for (i = 0; i < fileNum; i++) {
                printf("%s\n", fileName[i]);
            }
            #endif
            transfer_file(fileName, fileNum, pointSession);
            break;
            case 'h':
            printf("-f : transfer file to remote point\n");
        }
    }
    else if(buflen-1 > 0)
        rudp_sendto(pointSession->rsocket, buf, buflen-1, pointSession->friend);
    return 0;
}

int main(int argc, char* argv[])
{
//    printf("yes\n");
    int port;
    int socketfd;
    struct UdpClient *clientSession = malloc(sizeof(struct UdpClient));
    /* get address,port and poolid */
    port = atoi(argv[2]);
    if(strlen(argv[3])>=4){
        fprintf(stderr, "pool_id to long\n");
        return(0);
    }
    strcpy(clientSession->pool_id, argv[3]);
    struct sockaddr_in server;
    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(argv[1]);
    //memcpy(&server->sin_addr, addr, sizeof(struct in_addr));
    clientSession->server = &server;

    /* connect to servers */
    socketfd = (int)connect_to_server(clientSession);
    if(socketfd < 0){
        fprintf(stderr, "connect to server error\n");
        goto connectErr;
    }
    /* create the rudp */
    if((clientSession->rsocket=rudp_socket_from_socketfd(socketfd)) <= 0){
        fprintf(stderr, "create rudp error\n");
        goto rudpErr;
    }

    /* set receive handle */
    rudp_recvfrom_handler(clientSession->rsocket, receiver_handle);

    /* set event handle */
    rudp_event_handler(clientSession->rsocket, eventhandler);

    /* register stdio event handle */
    event_fd(STDIN_FILENO, io_handle, (void *)clientSession, "get Input");

    /* send thing */
    sendMsg(clientSession);

    printf("parent process start loop\n");
    eventloop(0);


rudpErr:
    free(clientSession->friend);
connectErr:
    free(clientSession);
    return 0;
}
