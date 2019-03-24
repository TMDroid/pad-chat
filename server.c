#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>

#define MAX_CONNECTIONS 32

//#define PORT 9034   // port we're listening on
fd_set mainSocketSet;   // mainSocketSet file descriptor list
fd_set readSocketsSet; // temp file descriptor list for select()
struct sockaddr_in myaddr;     // server address
struct sockaddr_in remoteaddr; // client address
int master_socket;     // listening socket descriptor
char buf[1024], tmpbuf[256];    // buffer for client data
int ret;
int yes = 1;        // for setsockopt() SO_REUSEADDR, below

struct _client {
    char *ip;
    char *username;
    char *password;

    /**
     * Etapa de comunicare la care se afla
     * 0 - neconectat
     * 1 - conectare initiala, iau @see(ip), asptet @username(username)
     * 2 - @see(username) oferit, astept @see(password)
     * 3 - @see(password) oferita, verific daca @see(username) exista deja si daca @see(password) data e corecta
     *        - daca exista si @see(password) e corecta -> il pun pe activ
     *        - daca exista dar @see(password) nu e corecta -> il trec in @see(stage) = 2 si incrementez @see(wrong),
     *              la @see(wrong) == 3 nu mai accept conexiuni de la acel @see(ip)
     *        - daca nu exista atunci creez @see(_client) cu @see(username) si @see(password) specificate
     *
     * 4 - conectat si poate trimite/primi mesaje
     *
     *  La deconectare il trec iar @see(stage) = 0
     */
    int stage;
    int wrong;

    int fd;
};


int activity;

int connected_clients = 0;
struct _client *connections[MAX_CONNECTIONS];

int db_items = 0;
struct _client *db[MAX_CONNECTIONS];

char *banned[MAX_CONNECTIONS];
int banned_ips = 0;

int socket_port;
int current_connection = -1;


struct sockaddr_in getSocketName(int s, bool local_or_remote) {
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    int ret;

    memset(&addr, 0, sizeof(addr));
    ret = (local_or_remote == true ? getsockname(s, (struct sockaddr *) &addr, (socklen_t *) &addrlen) :
           getpeername(s, (struct sockaddr *) &addr, (socklen_t *) &addrlen));
    if (ret < 0)
        perror("getsock(peer)name");
    return addr;
}

char *getIPAddress(int s, bool local_or_remote) {
    struct sockaddr_in addr;
    addr = getSocketName(s, local_or_remote);
    return inet_ntoa(addr.sin_addr);
}

void byebye(struct _client *);

/**
 * Initializare socket
 */
void init_socket() {
    FD_ZERO(&readSocketsSet);

    /**
     * Initializam socketul principal care va asculta pentru conexiuni noi de la clienti
     */
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Nu am putut creea socketul principal");
        exit(2);
    }

    /**
     * Deschidem socketul spre a putea fi refolosit de mai multe conexiuni
     */
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        perror("Nu am putut seta socketul ca refolosibil");
        exit(3);
    }

    /**
     * Ne legam la portul specificat
     */
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = INADDR_ANY;
    myaddr.sin_port = htons(socket_port);
    if (bind(master_socket, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
        perror("Nu am putut sa ma leg la portul dat ca parametru:");
        exit(4);
    }

    /**
     * Incepem sa ascultam pe socket dupa conexiuni care vin spre noi
     */
    if (listen(master_socket, MAX_CONNECTIONS) < 0) {
        perror("Nu pot asculta pe socket");
        exit(5);
    }
}

/**
 * Setez toti descriptorii din vectorul connections pe 0 in vector
 */
void init_connections() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        memset(&connections[i], 0, sizeof(struct _client));
    }
}

/**
 * Returneaza un FILE* cu fisierul de baza de date
 * @param write
 * @return
 */
FILE *getDatabaseFile(bool write) {
    FILE *database = fopen(".database", write ? "a" : "r");
    if (!database) {
        char *message = "Couldn't open database file";
        perror(message);
        return NULL;
    }

    return database;
}


/**
 * adaug clientul in fisierul cu clienti(baza de date)
 * @param client
 */
bool saveClient(struct _client *client) {
    FILE *database = getDatabaseFile(true);
    if (!database) {
        char message[256];
        sprintf(message, "Couldn't open database file to write user: %s", client->username);
        perror(message);
        return false;
    }

    size_t size = strlen(client->username) + strlen(client->password) + 2;
    char *line = (char *) malloc(size);
    sprintf(line, "%s|%s\n", client->username, client->password);
    line[size] = 0;

    int wrote = fprintf(database, line);
    fclose(database);

    db[db_items++] = client;

    return wrote > 0;
}

/**
 * Cauta un client in baza de date incarcata din fisier
 *
 * @param username
 * @return
 */
struct _client *getClientFromDatabase(char *username) {
    for (int i = 0; i < db_items; i++) {
        struct _client *client = db[i];

        if (strcmp(client->username, username) == 0) {
            return client;
        }
    }

    return NULL;
}

/**
 * Citeste baza de date din fisier si o incarca in memorie ca sa putem sa o accesam usor
 */
void read_database() {
    FILE *database = getDatabaseFile(false);
    if (!database) {
        perror("Cannot find database file");
        return;
    }

    char line[256];
    while (fgets(line, 255, database) != NULL && !feof(database)) {
        char *split = strstr(line, "|");
        if(!split) continue;

        *split = '\0';
        char *username = line;
        char *password = split + 1;
        password[strlen(password) - 1] = '\0';

        struct _client *client = (struct _client *) malloc(sizeof(struct _client));
        client->username = strdup(username);
        client->password = strdup(password);
        client->stage = 0;
        client->wrong = 0;
        client->fd = -1;
        client->ip = NULL;

        db[db_items++] = client;
    }

    fclose(database);
}


/**
 * Reinitializeaza setul de descriptori pentru a-l pregati pentru select
 */
void refreshDescriptorsForSelect() {
    FD_ZERO(&readSocketsSet);

    FD_SET(master_socket, &readSocketsSet);
    for (int i = 0; i < connected_clients; i++) {
        FD_SET(connections[i]->fd, &readSocketsSet);
    }
}

/**
 * Extrage cea mai mare valoare de descriptor din vectorul de conectari pentru a fi folosita in select
 * @return int
 */
int getMaxConnectionDescriptor() {
    int maxfd = master_socket;

    for (int i = 0; i < connected_clients; i++) {
        if (maxfd < connections[i]->fd) {
            maxfd = connections[i]->fd;
        }
    }

    return maxfd;
}

/**
 * Sterge conexiune din vectorul de conexiuni, eliberand si memoria dinamic alocata
 * @param connection
 */
void removeConnection(struct _client *connection) {
    for (int i = 0; i < connected_clients; i++) {
        struct _client *client = connections[i];

        /**
         * Caut socket-ul cu fd-ul cerut
         */
        if (client->fd == connection->fd) {

            /**
             * Si cand l-am gasit il elimin din vector
             */
            for (int j = i; j < connected_clients - 1; j++) {
                connections[j] = connections[j + 1];
            }
            connected_clients--;

            /**
             * Si din pool-ul meu de descriptori
             */
//            FD_CLR(client->fd, &mainSocketSet);
            close(client->fd);

            free(client);
            memset(client, 0, sizeof(struct _client));
            return;
        }
    }
}

/**
 * Apelata cand o conexiune este oprita fortt
 * @param connection
 */
void connectionKilled(struct _client *connection) {
    printf("<PAD-CHAT>: clientul %d a intrerupt conexiunea\n", connection->fd);
    byebye(connection);

    /**
     * Sterge din vectorul de clienti
     */
    removeConnection(connection);
}

/**
 * Functie care trimite un mesaj de @see(bytes) bytes pe socket-ul fd
 *
 * @param buf
 * @param bytes
 * @param fd
 * @return
 */
ssize_t sendMessage(char *buf, size_t bytes, int fd) {
    return send(fd, buf, bytes, 0);
}


/**
 * Functia trimite un mesaj tuturor in afara de master si socketul activ momentan
 * TODO: Vezi de ce nu merge sa trimita la ceilalti clienti conectati la server
 *
 * @param buf
 * @param nbytes
 */
void sendToALL(char *buf, size_t nbytes) {
    for (int i = 0; i < connected_clients; i++) {
        struct _client *client = connections[i];

//        if (FD_ISSET(client->fd, &mainSocketSet)) {
        /**
         * Filtram socketul master si pe al nostru
         */
        if (client->fd != current_connection) {

            ssize_t sent = sendMessage(buf, nbytes, client->fd);
            if (sent < 0) {
                perror("Sending error");
            }
//            }
        }
    }
}


/**
 * Cautam in tot vectorul de conexiuni active cea care a produs evenimentul care a intrerupt asteptarea functiei select
 */
struct _client *getActiveClient() {
    for (int i = 0; i < connected_clients; i++) {

        if (FD_ISSET(connections[i]->fd, &readSocketsSet)) {

            return connections[i];

        }

    }

    return NULL;
}

/**
 * Adauga ip la lista de banari ca sa nu mai acceptam conexiuni de la el
 * @param client
 */
void banIp(struct _client *client) {
    banned[banned_ips++] = client->ip;
}

/**
 * Verifica daca ip-ul dat ca parametru e banat
 *
 * @param toCheck
 * @return
 */
bool isBanned(char *toCheck) {
    for (int i = 0; i < banned_ips; i++) {
        char *ip = banned[i];

        if (strcmp(ip, toCheck) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Face un hash XOR-at al parolei fix la obtinerea acesteia dupa care se lucreaza doar cu acest hash
 *
 * @param password
 * @param key
 * @return
 */
char *hashPassword(char *password, char *key) {
    size_t messagelen = strlen(password);
    size_t keylen = strlen(key);

    char *encrypted = malloc(messagelen + 1);

    int i;
    for (i = 0; i < messagelen; i++) {
        encrypted[i] = password[i] ^ key[i % keylen];
    }
    encrypted[messagelen] = '\0';

    return encrypted;
}

/**
 * Functie care trimite notificari userului si celorlalti la un nou login/register
 *
 * @param client
 */
void clientLoggedIn(struct _client *client) {
    /**
     * Bun venit userului
     */
    char *message = "You have been successfully logged in\n";
    send(client->fd, message, strlen(message), 0);

    /**
     * Ii anuntam pe restul ca a venit un nou user
     */
    char annoucement[100];
    sprintf(annoucement, "\"%s\" has just joined chat\n", client->username);
    current_connection = client->fd;
    sendToALL(annoucement, strlen(annoucement));
    current_connection = -1;
}

/**
 * Incrementez contorul de greseli al parolei
 * La a 3a incrementare banam ip-ul
 *
 * @param client
 * @return
 */
bool incrementWrong(struct _client *client) {
    /**
     * Altfel inseamna ca parola e gresita si trebuie sa incrementam contorul de greseli
     */
    client->wrong++;

    /**
     * Daca a gresi parola de mai mult de 3 ori atunci ii banam ip-ul
     */
    if (client->wrong >= 3) {
        banIp(client);
        char *message = "You have been banned for too many password attempts";
        send(client->fd, message, strlen(message), 0);
        return true;
    }

    char *askPassword = "WRONG PASSWORD!!!\nPlease provide password for specified user: ";
    send(client->fd, askPassword, strlen(askPassword), 0);
    return true;
}

/**
 * Analizeaza conexiunea pentru a vedea daca vreo actiune intermediara este necesara.
 *
 * @param client
 * @return true|false -> in functie daca am consumat mesajul sau nu
 */
bool analyzeConnection(struct _client *client) {
    if(strlen(buf) == 0) {
        char *message = "Empty fields are not allowed: ";
        send(client->fd, message, strlen(message), 0);
        return true;
    };

    switch (client->stage) {
        case 1: //primesc username
            client->username = strdup(buf);
            client->stage = 2;

            char *askPassword = "Please provide password for specified user: ";
            send(client->fd, askPassword, strlen(askPassword), 0);
            return true;
        case 2:; //primesc parola
            char *password = strdup(hashPassword(buf, "9qmdoiIEcyE4TSTnKrky"));
            struct _client *fromDatabase = getClientFromDatabase(client->username);

            /**
             * Daca nu era deja in baza de date atunci inseamna ca e client nou, care nu a mai fost pana atunci
             * deci ii salvez noua parola si il adaug in database
             */
            if (fromDatabase == NULL) {
                client->password = password;
                client->stage = 4;

                saveClient(client);
                clientLoggedIn(client);
                return true;
            }


            /**
             * Daca clientul exista deja in database atunci verificam daca parola e buna.. Daca e cea corecta il bagam in chat
             */
            if (strcmp(password, fromDatabase->password) == 0) {
                client->password = password;
                client->stage = 4;

                clientLoggedIn(client);
                return true;
            } else {
                /**
                 * Daca parola nu e buna atunci ii mai dam o sansa(maxim 3)
                 */
                return incrementWrong(client);
            }

        default:
            return false;
    }
}

/**
 * Interpreteaza daca e vreo comanda speciala
 *
 * @param client
 * @return
 */
bool specialCommand(struct _client *client) {
    if(strcmp(buf, "/people") == 0) {
        char people[512];
        memset(people, 0, 512);

        strcpy(people, "People online:");

        for(int i = 0; i < connected_clients; i++) {
            struct _client *client1 = connections[i];

            sprintf(people, "%s\n%s", people, client1->username);
        }
        strcat(people, "\n");

        send(client->fd, people, strlen(people), 0);
        return true;
    }

    return false;
}



/**
 * Ia la revedere de la client si anunta pe restul de plecarea lui
 * @param client
 */
void byebye(struct _client *client) {
    /**
     * Mesaj lui
     */
    sprintf(buf, "Bye bye!!! Disconnecting...\n", client->fd, getIPAddress(client->fd, false));
    send(client->fd, buf, strlen(buf) + 1, 0);

    /**
     * Mesaj celorlalti
     */
    size_t read = sprintf(tmpbuf, "\"%s\" s-a deconectat din chat\n", client->username, false);
    current_connection = client->fd;
    sendToALL(tmpbuf, read);
    current_connection = -1;
}


/**
 * Verific daca userul cere sa fie deconectat. Daca da inchid socket-ul
 * @param client
 * @return
 */
bool checkDisconnection(struct _client *client) {
    /**
     * Verificam daca e o cerere de deconectare
     */
    if ((strncasecmp("QUIT\n", buf, 4) == 0)) {
        byebye(client);

        removeConnection(client);

        return true;
    }

    return false;
}

/**
 * Functie care preproceseaza mesajul primit de la client si daca a fost folosita una din partile ei(vreo functie), atunci nu mai
 * continuam cu trimiterea mai departe a mesajului la toata lumea.
 *
 * @param client
 * @return
 */
bool preprocessedMessage(struct _client *client) {
    /**
     * Inseamna ca am primit mesajul de la client si trebuie analizat in functie de statusul socket-ului
     * si retransmis la ceilalti clienti
     *
     * Daca mesajul a fost deja procesat in apelul de mai jos(checkDisconnection), atunci nu mergem mai departe
     */
    bool processed = analyzeConnection(client);
    processed = processed || specialCommand(client);


    /**
     * Verificam daca se deconecteaza clientul de la socket
     */
    bool wants_to_disconnect = checkDisconnection(client);

    return processed || wants_to_disconnect;
}

/**
 * O functie care se ocupa de gasirea client-ului de pe care s-a primit noul mesaj si decodificarea acestuia
 */
void handle_new_message() {

    /**
     * Cand am gasit-o salvam conexiunea intr-o variabila locala
     */
    struct _client *client = getActiveClient();
    if (!client) {
        return;
    }

    ssize_t read = 0;

    /**
     * Daca read <= 0 inseamna ca ori avem o eroare(-1) ori clientul a inchis conexiunea brusc (0)
     */
    if ((read = recv(client->fd, buf, sizeof(buf), 0)) <= 0) {
        /**
         * Clientul a inchis brusc conexiunea asa ca o eliminam din vector
         */
        if (read == 0) {
            connectionKilled(client);
        } else {
            perror("Eroare la citire din socket");
        }

        return;
    }

    /**
     * Setam NULL la final de string
     */
    buf[read - 2] = 0;
    //printf("%s\n",buf);

    if (preprocessedMessage(client)) return;

    /**
     * Daca nu e cerere de deconectare, atunci trimitem mai departe la toti mesajul pe care l-a trimis clientul nostru
     */
    current_connection = client->fd;
    read = sprintf(tmpbuf, "%s: %s\n", client->username, buf);

    printf("Received from some client: %s", tmpbuf);

    sendToALL(tmpbuf, (size_t) (read + 1));
    current_connection = -1;
}

/**
 * Functie care creaza o conexiune noua si o pune in vectorul de conexiuni
 */
void create_connection() {
    struct _client *newClient = (struct _client *) malloc(sizeof(struct _client));
    memset(newClient, 0, sizeof(struct _client));

    int newfd = 0, addrlen = sizeof(remoteaddr);
    if ((newfd = accept(master_socket, (struct sockaddr *) &remoteaddr, (socklen_t *) &addrlen)) < 0) {
        perror("accept");
    } else {
        char *ip = getIPAddress(newfd, false);
        /**
         * Verific daca nu e banned ip-ul
         */
        if (!isBanned(ip)) {

            newClient->ip = strdup(ip);
            newClient->fd = newfd;
            newClient->stage = 1;

            connections[connected_clients++] = newClient;

            sprintf(buf,
                    "Hi! Welcome to BSD-PAD-CHAT\nThere are %d other users connected\nPlease provide your username to login/register: ",
                    connected_clients - 1);

            send(newClient->fd, buf, strlen(buf) + 1, 0);
        } else {
            /**
             * Daca e banned atunci nu il las sa se logheze
             */

            char *message = "Your ip is banned and you are not allowed to connect again!";
            send(newfd, message, strlen(message), 0);
        }
    }
}


int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage:\n%s <numar port>\n", argv[0]);
        exit(1);
    }

    socket_port = atoi(argv[1]);
    init_socket();
    init_connections();
    read_database();

    /**
     * Un loop infinit in care asteptam pana cand primim ceva pe socket-ul principal sau pe vreuna din conexiunile deja
     * stabilite si luam o decizie in functie de aceasta
     */
    while (true) {
        refreshDescriptorsForSelect();

        /**
         * Functia select asteapta o perioada nedeterminata pana cand un eveniment se declanseaza pe unul din socketurile
         * din read_fds. Dupa declansarea unui eveniment, aceasta permite continuarea rularii programului pana cand se
         * ajunge iar in acest punct
         */
        int descriptorMax = getMaxConnectionDescriptor();
        activity = select(descriptorMax + 1, &readSocketsSet, NULL, NULL, NULL);

        printf("Errno = %d\n", errno);
        if (activity < 0 || (errno != EINTR && errno != 0)) {
            perror("Eroare la selectare socket la declansarea unui nou eveniment");
            errno = 0;
//            continue;
            //exit(6);
        }

        /**
         * Daca evenimentul a avut loc pe socket-ul principal atunci trebuie sa fie o incercare de conexiune noua
         */
        if (FD_ISSET(master_socket, &readSocketsSet)) {
            create_connection();
            continue;
        }

        /**
         * Altfel, inseamna ca unul din clientii deja conectati a transmis un mesaj care va trebui procesat
         */
        handle_new_message();
    }

}
 