#include <gtk/gtk.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

// Define constants for name length, message length, sending length, and max rooms
#define NAMELENGTH 51
#define MESSAGELENGTH 1024
#define SENDINGLENGTH 1024
#define MAX_ROOMS 10

// Structure to hold message data and whether it is a user message
typedef struct {
    char *message;
    gboolean is_user_message;
} MessageData;

// Function to handle errors during encryption/decryption
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt plaintext using AES-256-CBC
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    // Encrypt the message
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Function to decrypt ciphertext using AES-256-CBC
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    // Decrypt the message
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Global variables for signal flag, socket descriptor, and user name
volatile sig_atomic_t flag = 0;
int sockfd = 0;
char name[NAMELENGTH] = {};

// GTK widget pointers
GtkWidget *text_view;
GtkTextBuffer *text_buffer;
GtkWidget *entry;
GtkWidget *name_entry;
GtkWidget *room_entry;
GtkWidget *connect_button;
GtkWidget *send_button;
GtkWidget *name_label;
GtkWidget *room_label;

// AES key and IV
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
unsigned char *iv = (unsigned char *)"0123456789012345";

// Function to append a message to the text view with appropriate formatting
void append_to_text_view(const char *message, gboolean is_user_message) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(text_buffer, &end);

    GtkTextTag *tag = gtk_text_buffer_create_tag(text_buffer, NULL, NULL);
    if (is_user_message) {
        g_object_set(tag, "justification", GTK_JUSTIFY_RIGHT, "foreground", "blue", NULL);
    } else {
        g_object_set(tag, "justification", GTK_JUSTIFY_LEFT, "foreground", "green", NULL);
    }

    gtk_text_buffer_insert_with_tags(text_buffer, &end, message, -1, tag, NULL);
    gtk_text_buffer_insert(text_buffer, &end, "\n", -1);
}

// Wrapper function to be used with gdk_threads_add_idle for thread safety
gboolean append_to_text_view_wrapper(gpointer data) {
    MessageData *message_data = (MessageData *)data;
    append_to_text_view(message_data->message, message_data->is_user_message);
    g_free(message_data->message);
    g_free(message_data);
    return FALSE;
}

// Thread function to handle received messages
void *receivedMessageHandler(void *arg) {
    char receiveMessage[SENDINGLENGTH] = {};
    unsigned char decryptedMessage[SENDINGLENGTH + EVP_MAX_BLOCK_LENGTH] = {};
    int decrypted_length;    

    while (1) {
        int receive = recv(sockfd, receiveMessage, SENDINGLENGTH, 0);
        if (receive > 0 && !strstr(receiveMessage, "join") && !strstr(receiveMessage, "changeRoom")) {
            if (!strstr(receiveMessage, "capacity:")) {
                decrypted_length = decrypt((unsigned char *)receiveMessage, receive, key, iv, decryptedMessage);
                decryptedMessage[decrypted_length] = '\0';  

                MessageData *message_data = g_new(MessageData, 1);
                message_data->message = g_strdup((char *)decryptedMessage);
                message_data->is_user_message = FALSE;

                gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
            } else {
                MessageData *message_data = g_new(MessageData, 1);
                message_data->message = g_strdup(receiveMessage);
                message_data->is_user_message = FALSE;

                gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
            }
        } else if (receive == 0) {
            break;
        }
        memset(receiveMessage, 0, strlen(receiveMessage));
        memset(decryptedMessage, 0, strlen((char *)decryptedMessage));
    }
    return NULL;
}

// Function to send a message to the server
void send_message(const char *message) {
    char buffer[MESSAGELENGTH] = {};
    strncpy(buffer, message, MESSAGELENGTH);

    if (strstr(buffer, "changeRoom")) {
        send(sockfd, buffer, MESSAGELENGTH, 0);

        // Display the room change message in the sender's client
        char display_message[MESSAGELENGTH + 30];
        snprintf(display_message, sizeof(display_message), "You have switched to room %s", buffer + 11);

        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup(display_message);
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
    } else if (strstr(buffer, "showRooms")) {
        send(sockfd, buffer, MESSAGELENGTH, 0);

        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Room's status are\n");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
    } else if (strstr(buffer, "commands")) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Available commands are:\n changeRoom <Room number>\n showRooms\n");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
    } else if (strcmp(buffer, "exit") == 0) {
        flag = 1;
    } else {
        unsigned char encryptedMessage[MESSAGELENGTH + EVP_MAX_BLOCK_LENGTH];
        int encrypted_length = encrypt((unsigned char *)buffer, strlen(buffer), key, iv, encryptedMessage);
        send(sockfd, encryptedMessage, encrypted_length, 0);

        // Display the sent message in the sender's client
        char display_message[MESSAGELENGTH + NAMELENGTH + 10];
        snprintf(display_message, sizeof(display_message), "%s: %s", name, buffer);

        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup(display_message);
        message_data->is_user_message = TRUE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
    }
}

// Callback function for the send button click event
void on_send_button_clicked(GtkWidget *widget, gpointer data) {
    const char *message = gtk_entry_get_text(GTK_ENTRY(entry));
    send_message(message);
    gtk_entry_set_text(GTK_ENTRY(entry), "");
}

// Callback function for the room change button click event
void on_room_button_clicked(GtkWidget *widget, gpointer data) {
    const char *room_number = gtk_entry_get_text(GTK_ENTRY(room_entry));
    char message[MESSAGELENGTH];
    snprintf(message, sizeof(message), "changeRoom %s", room_number);
    send_message(message);
    gtk_entry_set_text(GTK_ENTRY(room_entry), "");
}

// Signal handler for SIGINT
void sigintdHandler(int sig) {
    flag = 1;
}

// Callback function for the connect button click event
void on_connect_button_clicked(GtkWidget *widget, gpointer data) {
    const char *username = gtk_entry_get_text(GTK_ENTRY(name_entry));
    const char *room_number_str = gtk_entry_get_text(GTK_ENTRY(room_entry));

    // Validate the username length
    if (strlen(username) < 3 || strlen(username) >= NAMELENGTH - 1) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Name must be more than three and less than 50 characters.");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
        return;
    }

    // Validate the room number
    int room_number = atoi(room_number_str);
    if (room_number < 1 || room_number > 10) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Room number must be between 1 and 10.");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
        return;
    }

    strncpy(name, username, NAMELENGTH);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Fail to create a socket.");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
        return;
    }

    // Socket information
    struct sockaddr_in serverInfo;
    int s_addrlen = sizeof(serverInfo);
    memset(&serverInfo, 0, s_addrlen);
    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverInfo.sin_port = htons(8888);

    // Connect to Server
    int err = connect(sockfd, (struct sockaddr *)&serverInfo, s_addrlen);
    if (err == -1) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Cannot connect to the server. Please try again!");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
        return;
    }

    send(sockfd, name, NAMELENGTH, 0);
    send(sockfd, &room_number, sizeof(room_number), 0);

    // Create a thread to handle received messages
    pthread_t receiveMessageThread;
    if (pthread_create(&receiveMessageThread, NULL, receivedMessageHandler, NULL) != 0) {
        MessageData *message_data = g_new(MessageData, 1);
        message_data->message = g_strdup("Create pthread error!");
        message_data->is_user_message = FALSE;

        gdk_threads_add_idle(append_to_text_view_wrapper, message_data);
        return;
    }

    // Display initial messages in the sender's client
    char room_message[100];
    snprintf(room_message, sizeof(room_message), "You have entered room %d", room_number);

    MessageData *message_data = g_new(MessageData, 1);
    message_data->message = g_strdup(room_message);
    message_data->is_user_message = FALSE;

    gdk_threads_add_idle(append_to_text_view_wrapper, message_data);

    message_data = g_new(MessageData, 1);
    message_data->message = g_strdup("Connected to server.");
    message_data->is_user_message = FALSE;

    gdk_threads_add_idle(append_to_text_view_wrapper, message_data);

    // Hide the connection-related widgets and show the chat-related widgets
    gtk_widget_hide(name_label);
    gtk_widget_hide(name_entry);
    gtk_widget_hide(room_label);
    gtk_widget_hide(room_entry);
    gtk_widget_hide(connect_button);
    gtk_widget_show(send_button);
    gtk_widget_show(entry);
}

int main(int argc, char *argv[]) {
    // Set up signal handler for SIGINT
    struct sigaction sa;
    sa.sa_handler = sigintdHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Error setting up SIGINT handler: ");
        exit(EXIT_FAILURE);
    }

    // Initialize GTK
    gtk_init(&argc, &argv);

    // Create main window
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "10 Rooms");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Create a vertical box container
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Create a scrolled window for the text view
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy    (GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    // Create a text view for displaying messages
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);

    text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));

    // Create and add widgets for name entry and room selection
    name_label = gtk_label_new("Name:");
    gtk_box_pack_start(GTK_BOX(vbox), name_label, FALSE, FALSE, 0);

    name_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), name_entry, FALSE, FALSE, 0);

    room_label = gtk_label_new("Room Number (1-10):");
    gtk_box_pack_start(GTK_BOX(vbox), room_label, FALSE, FALSE, 0);

    room_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), room_entry, FALSE, FALSE, 0);

    // Create and add connect button
    connect_button = gtk_button_new_with_label("Connect");
    g_signal_connect(connect_button, "clicked", G_CALLBACK(on_connect_button_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), connect_button, FALSE, FALSE, 0);

    // Create and add entry and send button for messages
    entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);

    send_button = gtk_button_new_with_label("Send");
    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_button_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), send_button, FALSE, FALSE, 0);

    // Show all widgets in the main window
    gtk_widget_show_all(window);

    // Hide the message entry and send button initially
    gtk_widget_hide(send_button);
    gtk_widget_hide(entry);

    // Enter GTK main loop
    gtk_main();

    // Close the socket when the application exits
    close(sockfd);
    return 0;
}


