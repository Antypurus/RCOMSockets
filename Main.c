
#include <sys/types.h>
#include <sys/socket.h>

int main(){

    int socketFD = -1;
    struct addrinfo hints, *servinfo,*p;
    int rv;

    memset(&hints, 0 , sizeof hints);
    hints.ai_family = AF_UNSPEC;//let the system decide between ipv4 and ipv6
    hints.ai_socktype = SOCK_STREAM;//FTP is on the FTP stack , therefore we use stream sockets and not datagram sockets(UDP)

    rv = getaddrinfo("www.google.com","http",&hints,&servinfo);
    if(rv!=0){
        perror("Failed to obtain address information\n");
        exit(-1);
    }

    //servinfo is a linked list of structs as such we must look for the first entry we can connect to
    for( p = servinfo; p!=NULL;p=p->ai_next){
        socketFD = socket(p->ai_family,p->ai_socktype,p->ai_protocol);//address family ,Socket Type ,protocol 
        if(socketFD==-1){
            perror("Socket");
            continue;
        }

        rv=connect(socketFD,p->ai_addr,p->ai_addrlen);// socket file descriptor,address to connect to,address length(determined by address family)
        if(rv==-1){
            perror("Connect");
            close(socketFD);//no points in keeping this specific socket open as we cant connet to this address
            continue;
        }

        break;
    }

    if(p==NULL){
        //was unable to find a single address that we could connect to
        print("failed to obtain address to connect to\n");
        exit(-1);
    }

    freeaddrinfo(servinfo);//getaddrinfo creates a linked list as such its elements are dynamically allocates so we must free them when we no longer need them
    return 0;
}