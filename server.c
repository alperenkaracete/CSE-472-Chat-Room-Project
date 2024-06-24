#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

//encrypt function
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
//decrypt function
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

#define NAMELENGTH 51
#define MESSAGELENGTH 1024
#define SENDINGLENGTH 1024
#define MAX_ROOMS 10
#define MAX_CLIENTS 100

//clietn structure keeps client infos
typedef struct clientNode {
    int data;
    int roomNumber;
    struct clientNode* prev;
    struct clientNode* next;
    char ip[16];
    char name[NAMELENGTH];
} ClientList;

typedef struct {
    int client_socket;
    int room_number;
} ClientInfo;

ClientInfo clients[MAX_CLIENTS];

ClientList *newNode(int sockfd, char* ip) {
    ClientList *list = (ClientList *)malloc(sizeof(ClientList));
    list->data = sockfd;
    list->prev = NULL;
    list->next = NULL;
    strncpy(list->ip, ip, sizeof(list->ip) - 1);  
    list->ip[sizeof(list->ip) - 1] = '\0';  
    strncpy(list->name, "NULL", sizeof(list->name) - 1); 
    list->name[sizeof(list->name) - 1] = '\0'; 
    return list;
}


int server_sockfd = 0, client_sockfd = 0;
ClientList *root, *previousNode;

//ctrl c handler
void sigintdHandler(int sig) {
    ClientList *temp;
    while (root != NULL) {
        printf("\nClose socketfd: %d\n", root->data);
        close(root->data); // close all sockets including server_sockfd
        temp = root;
        root = root->next;
        free(temp);
    }
    printf("Server closed successfully.\n");
    exit(EXIT_SUCCESS);
}

#define KEY_LENGTH 32
#define IV_LENGTH 16

unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // Example key (32 bytes)
unsigned char *iv = (unsigned char *)"0123456789012345";

//Sending messages one client to other clients except itself from server.Before sending encrypt it.
void sendMessageToRoom(ClientList *sender, char temp_buffer[]) {
    ClientList *temp = root->next;
    unsigned char encrypted_message[MESSAGELENGTH + EVP_MAX_BLOCK_LENGTH];
    int encrypted_length;

    while (temp != NULL) {
        if (sender->data != temp->data && sender->roomNumber == temp->roomNumber) {
            encrypted_length = encrypt((unsigned char *)temp_buffer, strlen(temp_buffer), key, iv, encrypted_message);
            printf("Message sent to socket number %d: \"%s\" \n", temp->data, temp_buffer);
            send(temp->data, encrypted_message, encrypted_length, 0);
        }
        temp = temp->next;
    }
}

//Send room client counts
void sendRoomCapacityToClient(int senderSock, char roomStatus[]) {

    send(senderSock, roomStatus, strlen(roomStatus)+1, 0);
    
}
//Count client in rooms
void countClientsInRooms(int socketNo) {
    char tempBuf[SENDINGLENGTH];
    char buffer[SENDINGLENGTH];
    memset(buffer, 0, sizeof(buffer)); // Initialize buffer with null bytes
    for (int room_number = 1; room_number <= MAX_ROOMS; room_number++) {
        int count = 0;
        ClientList *temp = root->next;
        while (temp != NULL) {
            if (temp->roomNumber == room_number) {
                count++;
            }
            temp = temp->next;
        }
        snprintf(tempBuf, SENDINGLENGTH, "Room %d capacity: %d\n", room_number, count);
        strcat(buffer, tempBuf); // Concatenate tempBuf to buffer
    }
    strcat(tempBuf,"\0");
    sendRoomCapacityToClient(socketNo, buffer); // Send the concatenated buffer
}

//Create thread for every joined clients.
void clientHandler(void *p_client) {
    int leaveFlag = 0;
    char nickname[NAMELENGTH] = {};
    char receivedBuffer[MESSAGELENGTH] = {};
    char sendBuffer[SENDINGLENGTH] = {};
    ClientList *list = (ClientList *)p_client;

    unsigned char encryptedBuffer[MESSAGELENGTH + EVP_MAX_BLOCK_LENGTH];
    unsigned char decryptedBuffer[MESSAGELENGTH + EVP_MAX_BLOCK_LENGTH];
    int encrypted_length;
    int decrypted_length;

    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; 
    unsigned char *iv = (unsigned char *)"0123456789012345";

    // Naming
    if (recv(list->data, nickname, NAMELENGTH, 0) <= 0 || strlen(nickname) < 3 || strlen(nickname) >= NAMELENGTH-1) {
        printf("%s didn't input name.\n", list->ip);
        leaveFlag = 1;
    }

    if (recv(list->data, &(list->roomNumber), sizeof(list->roomNumber), 0) == -1) {
        printf("Error getting room number. Exiting.\n");
        leaveFlag = 1;
    } 

    else {
        strncpy(list->name, nickname, NAMELENGTH);
        printf("%s(%s)(%d) join the chatroom.\n", list->name, list->ip, list->data);
        sprintf(sendBuffer, "%s(%s) join the chatroom.", list->name, list->ip);
        sendMessageToRoom(list, sendBuffer);
    }

    // Conversation
    while (1) {
        if (leaveFlag) {
            break;
        }
        int receive = recv(list->data, receivedBuffer, MESSAGELENGTH, 0);
        if (receive > 0 && !strstr(receivedBuffer,"changeRoom") && !strstr(receivedBuffer,"showRooms") ) {
            decrypted_length = decrypt((unsigned char *)receivedBuffer, receive, key, iv, decryptedBuffer);
            decryptedBuffer[decrypted_length] = '\0'; // Null-terminate the decrypted message

            if (strlen((char *)decryptedBuffer) == 0) {
                continue;
            }
            snprintf(sendBuffer, SENDINGLENGTH, "> %s: %s", list->name, decryptedBuffer);
            sendMessageToRoom(list, sendBuffer);
        } else if (receive == 0 || strcmp(receivedBuffer, "exit") == 0) {
            printf("%s(%s)(%d) leave the chatroom.\n", list->name, list->ip, list->data);
            sprintf(sendBuffer, "%s(%s) leave the chatroom.", list->name, list->ip);
            sendMessageToRoom(list, sendBuffer);
            leaveFlag = 1;
        } else if (strstr(receivedBuffer,"changeRoom")){
            char tempRoom[100];
            strcpy(tempRoom,receivedBuffer);
            char *token;
            token = strtok(tempRoom," \n");
            token = strtok(NULL," \n");
            strcpy(tempRoom,token);
            int roomNo = atoi(tempRoom);
            printf("%s(%s)(%d) leave the chatroom.\n", list->name, list->ip, list->data);
            sprintf(sendBuffer, "%s(%s) leave the chatroom.", list->name, list->ip);
            sendMessageToRoom(list, sendBuffer);
            list->roomNumber = roomNo;
            printf("User %s change her/his room.\n",list->name);
            strncpy(list->name, nickname, NAMELENGTH);
            printf("%s(%s)(%d) join the chatroom.\n", list->name, list->ip, list->data);
            sprintf(sendBuffer, "%s(%s) join the chatroom.", list->name, list->ip);
            sendMessageToRoom(list, sendBuffer);            
            
        } else if (!strcmp(receivedBuffer,"showRooms")){
            countClientsInRooms(list->data);

        } else {
            printf("Fatal Error: -1\n");
            leaveFlag = 1;
        }
    }

    // Remove Node
    close(list->data);
    if (list == previousNode) { // remove an edge node
        previousNode = list->prev;
        previousNode->next = NULL;
    } else { // remove a middle node
        list->prev->next = list->next;
        list->next->prev = list->prev;
    }
    free(list);
}

int main() {
    struct sigaction sa;
    sa.sa_handler = sigintdHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Error setting up SIGINT handler: ");
        exit(EXIT_FAILURE);
    }

    // Create socket
    server_sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (server_sockfd == -1) {
        printf("Fail to create a socket.");
        exit(EXIT_FAILURE);
    }

    // Socket information
    struct sockaddr_in serverInfo, clientInfo;
    int s_addrlen = sizeof(serverInfo);
    int c_addrlen = sizeof(clientInfo);
    memset(&serverInfo, 0, s_addrlen);
    memset(&clientInfo, 0, c_addrlen);
    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(8888);

    // Bind and Listen
    bind(server_sockfd, (struct sockaddr *)&serverInfo, s_addrlen);
    listen(server_sockfd, 5);

    // Print Server IP
    getsockname(server_sockfd, (struct sockaddr*) &serverInfo, (socklen_t*) &s_addrlen);
    printf("Start Server on: %s:%d\n", inet_ntoa(serverInfo.sin_addr), ntohs(serverInfo.sin_port));

    // list for clients
    root = newNode(server_sockfd, inet_ntoa(serverInfo.sin_addr));
    previousNode = root;

    //Get clients
    while (1) {
        client_sockfd = accept(server_sockfd, (struct sockaddr*) &clientInfo, (socklen_t*) &c_addrlen);

        getpeername(client_sockfd, (struct sockaddr*) &clientInfo, (socklen_t*) &c_addrlen);
        printf("Client %s:%d come in.\n", inet_ntoa(clientInfo.sin_addr), ntohs(clientInfo.sin_port));

        ClientList *currentNode = newNode(client_sockfd, inet_ntoa(clientInfo.sin_addr));
        currentNode->prev = previousNode;
        previousNode->next = currentNode;
        previousNode = currentNode;

        pthread_t id;
        if (pthread_create(&id, NULL, (void *)clientHandler, (void *)currentNode) != 0) {
            perror("Create pthread error!\n");
            exit(EXIT_FAILURE);
        }
        sleep(1); // avoid busy waiting
    }

    return 0;
}
