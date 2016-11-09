//HW #: HW 11(Buffer Overflow) (ECE 404 Spring 2015)
//Name: Sthitapragyan Parida
//ECN Login: sparida
//Due Date: 4/14/2015
//Note: Search for changes using Change in find bar, couldnt hightlight for some reason

/*
/ file : server.c
/------------------------------------------
/ This is a server socket program that echos recieved messages
/ from the client.c program.  Run the server on one of the ECN
/ machines and the client on your laptop.
*/

// For compiling this file:
//        Linux:               gcc server.c -o server
//        Solaris:             gcc server.c -o server -lsocket

// For running the server program:
//
//                server 9000
//
// where 9000 is the port you want your server to monitor.  Of course,
// this can be any high-numbered that is not currently being used by others.

#include <stdio.h> 
//MODIFIED SERVER CODE

#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/wait.h> 
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_PENDING 10     /* maximun # of pending for connection */
#define MAX_DATA_SIZE 5

int DataPrint(char *recvBuff,char *str, int numBytes);
 
int main(int argc, char *argv[])
{
    if (argc < 2) {
    fprintf(stderr,"ERROR, no port provided\n");
    exit(1);
    }
    int PORT = atoi(argv[1]);

    char *recvBuff; /* recv data buffer */
    int numBytes = 0; 
    int senderBuffSize;
    //char str[MAX_DATA_SIZE];
    //Change 1
    // Buffer overflow is possible as explained below
    // str needs to be a pointer because teh received bytes can be as large as possible and therefore fixing the max size of str can lead to buffer oveflow when using strcpy. Otherwise if more than the max bytes allowed for str are sent, strcpy copies into memory which is not part of str and thus teh possibility of a buffer overflow arises. Initially without pointer change, mulitple word entries into str closed the program where as after using dynamic memory allocation, that stops.
    char *str;
    int servSockfd, clntSockfd;  
    struct sockaddr_in sevrAddr;    
    struct sockaddr_in clntAddr; 
    int clntLen;
    socklen_t optlen = sizeof senderBuffSize;

    /* make socket */
    if ((servSockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("sock failed");
        exit(1);
    }

    /* set IP address and port */
    sevrAddr.sin_family = AF_INET;       
    sevrAddr.sin_port = htons(PORT);     
    sevrAddr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(sevrAddr.sin_zero), 8);       

    if (bind(servSockfd, (struct sockaddr *)&sevrAddr, 
                sizeof(struct sockaddr)) == -1) {
        perror("bind failed");
        exit(1);
    }

    if (listen(servSockfd, MAX_PENDING) == -1) {
        perror("listen failed");
        exit(1);
    }

    while(1) {
        clntLen = sizeof(struct sockaddr_in);
        if ((clntSockfd = accept(servSockfd, 
                    (struct sockaddr *) &clntAddr, &clntLen)) == -1) {
            perror("accept failed");
            exit(1);
        }
        printf("Connected from %s\n", inet_ntoa(clntAddr.sin_addr));

	if (send(clntSockfd, "Connected!!!\n", 
                    strlen("Connected!!!\n"), 0) == -1) {
		perror("send failed");
		close(clntSockfd);
		exit(1);
	}

        /* repeat for one clinet service */
        while(1) {

            /* recv data from the client */
            getsockopt(clntSockfd, SOL_SOCKET,SO_SNDBUF, 
            &senderBuffSize, &optlen); /* check sender buffer size */
            recvBuff = malloc(senderBuffSize * sizeof (char));
            if ((numBytes = 
                    recv(clntSockfd, recvBuff, senderBuffSize, 0)) == -1) {
                perror("recv failed");
                exit(1);
            }

            recvBuff[numBytes] = '\0';

            //Change 2
            //As str is a pointer it is necessary to allocate memory for it [The size of teh received bytes]
            str = malloc(senderBuffSize * sizeof (char));    

            //Change 3
            // Makes sure enough memeory is allocated, before copying
            if (str != NULL) strcpy(str, recvBuff);
            
            /* send data to the client */
            if (send(clntSockfd, str, strlen(str), 0) == -1) {
                perror("send failed");
                close(clntSockfd);
                exit(1);
        }

        if(DataPrint(recvBuff, str, numBytes)){
            fprintf(stderr,"ERROR, no way to print out\n");
            exit(1);
        }
    }

    close(clntSockfd);  
    exit(1);
    }
}

int DataPrint(char *recvBuff,char *str, int numBytes) {
    printf("RECEIVED: %s", recvBuff);
    printf("SENT: %s", str);
    printf("RECEIVED BYTES: %d\n\n", numBytes);
    return(0);
}
