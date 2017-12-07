
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define FTP_PORT "21"

//Types for generic usage
typedef int SOCKET_FILE_DESC;

//FTP request information types
typedef char *FTP_URL_ADDRESS;
typedef char *FTP_USERNAME;
typedef char *FTP_PASSWORD;
typedef char *FTP_REQUEST_FILEPATH;

//structure that holds the various information required to establish FTP connection and download the file
typedef struct FTP_REQUEST_INFORMATION
{
    FTP_URL_ADDRESS         address;       //string containing address to the FTP server
    FTP_USERNAME            username;         //string with the login username for the FTP server
    FTP_PASSWORD            password;         //string with the login password for the FTP server
    FTP_REQUEST_FILEPATH    filepath; //string with the filepath to download from the FTP server
} FTP_REQUEST_INFORMATION;

SOCKET_FILE_DESC getFTPServerSocket(FTP_URL_ADDRESS address)
{
    SOCKET_FILE_DESC socketFD = -1;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family     =   AF_UNSPEC;     //let the system decide between ipv4 and ipv6
    hints.ai_socktype   =   SOCK_STREAM; //FTP is on the FTP stack , therefore we use stream sockets and not datagram sockets(UDP)

    //rv = getaddrinfo("dservers.ddns.net", FTP_PORT, &hints, &servinfo);
    //rv = getaddrinfo("178.166.2.240", FTP_PORT, &hints, &servinfo);

    rv = getaddrinfo(address, FTP_PORT, &hints, &servinfo);

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

int main()
{
    SOCKET_FILE_DESC fd = getFTPServerSocket("dservers.ddns.net");
    printf("Socket File Descriptor:%d\n",fd);
    return 0;
}