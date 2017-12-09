
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define FTP_PORT_NUMBER "21"

//Types for generic usage
typedef int SOCKET_FILE_DESC;

//FTP request information types
typedef char*           FTP_URL_ADDRESS;
typedef char*           FTP_USERNAME;
typedef char*           FTP_PASSWORD;
typedef char*           FTP_REQUEST_FILEPATH;
typedef char*           FTP_PORT;
typedef char*           FTP_COMMAND;
typedef unsigned short  FTP_SERVER_CODE;
typedef unsigned int    FTP_PASSWORD_LENGTH;
typedef unsigned int    FTP_USERNAME_LENGTH;
typedef unsigned int    FTP_COMMAND_LENGTH;

//structure that holds the various information required to establish FTP connection and download the file
typedef struct FTP_REQUEST_INFORMATION
{
    FTP_PORT                port;       //string containing port number for the FTP server connection
    FTP_URL_ADDRESS         address;    //string containing address to the FTP server
    FTP_USERNAME            username;   //string with the login username for the FTP server
    FTP_PASSWORD            password;   //string with the login password for the FTP server
    FTP_REQUEST_FILEPATH    filepath;   //string with the filepath to download from the FTP server
} FTP_REQUEST_INFORMATION;

/*
    This function takes the address and port number and creates a socket and connects it to that server.
    Then it returns the Socket File Descriptor to the connected socket

    Parameters:
        address =   A string containing the server address in either URL or IP format
        port    =   The port number to connect to.

    Return:
        - The File descriptor for the Socket Connected to the specified server
*/
SOCKET_FILE_DESC getFTPServerSocket(FTP_URL_ADDRESS address, FTP_PORT port)
{
    SOCKET_FILE_DESC socketFD = -1;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family     =   AF_UNSPEC;     //let the system decide between ipv4 and ipv6
    hints.ai_socktype   =   SOCK_STREAM; //FTP is on the FTP stack , therefore we use stream sockets and not datagram sockets(UDP)

    //rv = getaddrinfo("dservers.ddns.net", FTP_PORT, &hints, &servinfo);
    //rv = getaddrinfo("178.166.2.240", FTP_PORT, &hints, &servinfo);

    rv = getaddrinfo(address, port, &hints, &servinfo);

    if (rv != 0)
    {
        perror("Failed to obtain address information\n");
        freeaddrinfo(servinfo);
        exit(-1);
    }

    //servinfo is a linked list of structs as such we must look for the first entry we can connect to
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        socketFD = socket(p->ai_family, p->ai_socktype, p->ai_protocol); //address family ,Socket Type ,protocol
        if (socketFD == -1)
        {
            perror("Socket");
            continue;
        }

        rv = connect(socketFD, p->ai_addr, p->ai_addrlen); // socket file descriptor,address to connect to,address length(determined by address family)
        if (rv == -1)
        {
            perror("Connect");
            close(socketFD); //no points in keeping this specific socket open as we cant connet to this address
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        //was unable to find a single address that we could connect to
        printf("failed to obtain address to connect to\n");
        freeaddrinfo(servinfo);
        return -1;
    }else{
        freeaddrinfo(servinfo);
        return socketFD;
    }

    freeaddrinfo(servinfo); //getaddrinfo creates a linked list as such its elements are dynamically allocates so we must free them when we no longer need them
    return -1;
}

/*
    This function send the passed command to the server via the passed socket file descriptor
*/
FTP_SERVER_CODE sendFTPCommand(SOCKET_FILE_DESC fd,FTP_COMMAND cmd){
    FTP_COMMAND_LENGTH length = strlen(cmd) + 1;    //obtain command lentgth
    unsigned int sent = send(fd,cmd,length,0);      //send command
    char msg[1000];
    unsigned int read = recv(fd,msg,1000,0);        //read server response
    if(sent==0 ||read==0)                           //error checking
    {
        printf("failed to send command or read response\n");
        return -1;
    }else{
        printf("Sent:%s\nReceived:%s",cmd,msg);
    }
    FTP_SERVER_CODE code;
    sscanf(msg,"%hu",&code);                        //isolate response code from code explanation message
    return code;
}

/*
DOCUMENTATION PENDING
*/
FTP_SERVER_CODE executeFTPlogin(SOCKET_FILE_DESC fd,FTP_USERNAME username,FTP_PASSWORD password){
    FTP_COMMAND userCMD = (FTP_COMMAND)malloc(usernameLength + 6);//the length of the username plus the length of the FTP command
    FTP_COMMAND passCMD = (FTP_COMMAND)malloc(passwordLength + 6);//the length of the password plus the length of the FTP command

    if (passCMD == NULL || userCMD==NULL)
    {
        free(passCMD);
        free(userCMD);
        printf("[ERROR]\tFailed To allocate command buffers\n");
        return -1;
    }
    //creating the user command to send to the server
    if(strcat(userCMD, "user ") == NULL)
    {
        free(passCMD);
        free(userCMD);
        printf("[ERROR]\tFailed To create user command\n");
        return -1;
    }
    if (strcat(userCMD, username) == NULL)
    {
        free(passCMD);
        free(userCMD);
        printf("[ERROR]\tFailed To create user command\n");
        return -1;
    }
    //creating the pass command to send to the server
    if (strcat(passCMD, "pass ") == NULL)
    {
        free(passCMD);
        free(userCMD);
        printf("[ERROR]\tFailed To create pass command\n");
        return -1;
    }
    if (strcat(passCMD, password) == NULL)
    {
        free(passCMD);
        free(userCMD);
        printf("[ERROR]\tFailed To create pass command\n");
        return -1;
    }

    FTP_SERVER_CODE code = sendFTPCommand(fd,userCMD);
    code = sendFTPCommand(fd,passCMD);

    return code; //this is an internal error and not a server error
}

int main()
{
    SOCKET_FILE_DESC fd = getFTPServerSocket("dservers.ddns.net",FTP_PORT_NUMBER);
    char read[1000];
    unsigned int reada = recv(fd, read, 1000, 0);
    printf("%s\n", read);

    memset(read, 0, sizeof(read));

    executeFTPlogin(fd, "dddt", "1080shitalhada%2");
    return 0;
}