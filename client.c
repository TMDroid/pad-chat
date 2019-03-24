/*
// Multiperson chat using select
// Client part
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT 8080

fd_set read_fds,master; // temp file descriptor list for select()
int sock;        //socket
struct sockaddr_in servaddr;
char buf[256];  // buffer for client data
int nbytes, ret;
int ipaddr;

void readkb(){
    if ( FD_ISSET(0, &read_fds) ) {
        nbytes = read(0, buf,sizeof(buf));
        buf[nbytes-1] = '\r';
        buf[nbytes] = '\n';
        ret = send(sock, buf, nbytes + 1,0);
        if (ret <= 0 ){
            perror("send");
            exit(1);
        }
    }
}

void readsock(){
    if ( FD_ISSET(sock, &read_fds) ) {
        nbytes = read(sock, buf, sizeof(buf));
        if (nbytes <= 0) {
            printf("Server has closed connection... closing...\n");
            exit(2);
        }
        write(1,buf, nbytes);
    }
}

void infiniteLoop(){
    for(;;) {
        read_fds = master;
        if (select(sock+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(1);
        }
// check if read from keyboard
        if (FD_ISSET(0, &read_fds)) {
            readkb();
        }
        else
// check if read from server
            readsock();
    }
}

void init_socket(){
// get the socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    memset(&servaddr,0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ipaddr;
    servaddr.sin_port = htons( PORT );
// connect to server
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) {
        perror("connect");
        exit(1);
    }
// add the listener to the master set
    FD_ZERO(&read_fds);    // clear the set
    FD_ZERO(&master);
    FD_SET(0, &master);      //Add a descriptor to set
    FD_SET(sock, &master);
}

char *getIpFromFile(){
    FILE *f;
    f=fopen("file.txt","r");
    if(!f)
        return NULL;
    else{
        fgets(buf,29,f);
        ipaddr = inet_addr(buf);
        char *magie=strdup(buf);
        fclose(f);
        return magie;
    }
}

int getIpFromArgs(char *arg){
    int ip = inet_addr(arg);
    printf("%s => %d ip address\n",arg,ip);
    if (ip == -1 ) {
        struct in_addr inaddr;
        struct hostent * host = gethostbyname( arg );
        if (host == NULL ) {
            printf("Error getting the host address\n");
            exit(1);
        }
        memcpy(&inaddr.s_addr, host->h_addr_list[0],sizeof(inaddr));
        printf("Connecting to %s ...\n",inet_ntoa( inaddr) );
        memcpy(&ip, host->h_addr_list[0],sizeof(unsigned long int)) ;
    }
    return ip;
}

void saveIp(char *arg){
    FILE *f;
    f=fopen("file.txt","r");
    if(!f){
        f=fopen("file.txt","w");
        fputs(arg,f);
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2 ) {
        ipaddr = inet_addr(getIpFromFile());
    }
    else{
        ipaddr=getIpFromArgs(argv[1]);
    }
    init_socket();
    saveIp(argv[1]);
    infiniteLoop();

    return 0;
}