
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
typedef char*           FTP_URL_FORMAT;
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
typedef unsigned char   FTP_ERROR;

//structure that holds the various information required to establish FTP connection and download the file
typedef struct FTP_REQUEST_INFORMATION
{
    FTP_ERROR               error;
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
    memset(msg, 0, sizeof(msg));                    //zero out the string so that there isnt any remnant unwanted data
    unsigned int read = recv(fd,msg,1000,0);        //read server response
    if(sent==0 ||read==0)                           //error checking
    {
        printf("failed to send command or read response\n");
        return -1;
    }else{
        printf("Sent:%s\nReceived:%s\n",cmd,msg);
    }
    FTP_SERVER_CODE code;
    sscanf(msg,"%hu",&code);                        //isolate response code from code explanation message
    return code;
}

FTP_PORT enterFTPPassiveMode(SOCKET_FILE_DESC fd){

}

/*
DOCUMENTATION PENDING
*/
FTP_SERVER_CODE executeFTPlogin(SOCKET_FILE_DESC fd,FTP_USERNAME username,FTP_PASSWORD password){
    FTP_USERNAME_LENGTH usernameLength = strlen(username) + 1;      //determine length of username
    FTP_PASSWORD_LENGTH passwordLength = strlen(username) + 1;      //determine length of password

    FTP_COMMAND userCMD = (FTP_COMMAND)malloc(usernameLength + 6);  //the length of the username plus the length of the FTP command
    FTP_COMMAND passCMD = (FTP_COMMAND)malloc(passwordLength + 6);  //the length of the password plus the length of the FTP command
    memset(userCMD, 0, usernameLength + 6);                         //zero the string buffer so as not to cause any issues
    memset(passCMD, 0, usernameLength + 6);                         //zero the string buffer so as not to cause any issues

    if (passCMD == NULL || userCMD == NULL)
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
    if(code != 331)
    {
        free(passCMD);
        free(userCMD);
        printf("Incorrect Server Response Issue sending command detected\n");
        return -1;
    }
    code = sendFTPCommand(fd,passCMD);
    if (code != 230)
    {
        free(passCMD);
        free(userCMD);
        printf("Incorrect Server Response Issue sending command detected\n");
        return -1;
    }

    free(passCMD);
    free(userCMD);
    return code; //this is an internal error and not a server error
}

FTP_REQUEST_INFORMATION parseFTPURL(FTP_URL_FORMAT url)
{
    size_t length = strlen(url)+1;
    FTP_USERNAME username = (FTP_USERNAME)malloc(length);
    FTP_PASSWORD password = (FTP_PASSWORD) malloc(length);
    FTP_URL_ADDRESS domain = (FTP_URL_ADDRESS)malloc(length);
    FTP_REQUEST_FILEPATH path = (FTP_REQUEST_FILEPATH)malloc(length);

    if(username == NULL || password == NULL || domain == NULL || path == NULL){
        free(username);
        free(password);
        free(domain);
        free(path);
        printf("Failed to allocate buffer\n");
        FTP_REQUEST_INFORMATION err;
        err.error = 1;
        return err;
    }

    sscanf(url, "ftp://%99[^:]:%99[^@]@%99[^/]/%99s", username, password, domain, path);
}

int main()
{
    char url[] = "ftp://dddt:1080shitalhada%2@dservers.ddns.net/path/patg";
    char username[1000];
    char password[1000];
    char domain[1000];
    char path[1000];
    sscanf(url,"ftp://%99[^:]:%99[^@]@%99[^/]/%99s",username,password,domain,path);
    printf("%s\n%s\n%s\n%s\n",username,password,domain,path);

    SOCKET_FILE_DESC fd = getFTPServerSocket("dservers.ddns.net", FTP_PORT_NUMBER);
    
    {
        char read[1000];
        memset(read, 0, sizeof(read));
        unsigned int reada = recv(fd, read, 1000, 0);
        printf("%s\n", read);
    }

    executeFTPlogin(fd, "dddt", "1080shitalhada%2");
    char msg[1000];
    memset(msg,0,sizeof(msg));
    send(fd,"pasv",5,0);
    recv(fd,msg,1000,0);
    printf("MSG:%s\n",msg);
    unsigned int arr[6];
    arr[0] = 0;
    arr[1] = 0;
    arr[2] = 0;
    arr[3] = 0;
    arr[4] = 0;
    arr[5] = 0;
    int code = 200;
    sscanf(msg, "%d Entering Passive Mode (%d,%d,%d,%d,%d,%d)", &code, &arr[0], &arr[1], &arr[2], &arr[3], &arr[4], &arr[5]);
    printf("%d \n%d \n%d \n%d \n%d \n%d \n%d\n", code, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
    return 0;
}