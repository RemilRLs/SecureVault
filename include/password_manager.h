// Allows you to manage the password manager, for example adding/modifying/deleting a password and other information

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <time.h>

#include "auth.h"
#include "utils.h"
#include "encryption.h"


#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#define DOMAIN_SIZE 50
#define LOGIN_SIZE 50
#define PASSWORD_SIZE 255
#define COMMENT_SIZE 255
#define PLAIN_TEXT_BUFFER_SIZE 2048
#define NUMBER_SECOND_IN_A_DAY 86400

#define CSV_EXPORT_FILE_PREFIX "./data/password_manager/CSV/passwords_"



typedef struct PasswordNode {
    unsigned int id;
    char domain[DOMAIN_SIZE];
    char login[LOGIN_SIZE];
    char password[PASSWORD_SIZE];
    char comment[COMMENT_SIZE];

    struct tm dateAdded;
    struct tm dateEdit;

    struct PasswordNode* next;
} PasswordNode;


PasswordNode* create_password_node(PasswordNode* head, const char* domain, const char* login, const char* password, const char* comment);
void add_password(PasswordNode** head, const char* domain, const char* login, const char* password, const char* comment);
void display_passwords(const PasswordNode* head);
void display_specific_node(PasswordNode* node);
void delete_password(PasswordNode** head);
void free_password_list(PasswordNode* head);
unsigned int get_id_number(PasswordNode *head);
char* generate_aleatory_passwd();
void search_node_password(PasswordNode* head);
void modify_node(PasswordNode *head);
PasswordNode* search_by_id(PasswordNode* head, unsigned int id);
PasswordNode* search_by_domain(PasswordNode* head, const char* domain);
PasswordNode* search_by_login(PasswordNode* head, const char* login);
void export_passwordnode_csv(PasswordNode *head, const char* authenticated_username);
void import_passwordnode_csv(PasswordNode **head, const char* authenticated_username);
void setup_user_password_file(const char* authenticated_username, unsigned char* iv);
void save_passwords_to_binary(PasswordNode* head, const char* filepath, const unsigned char* key, const unsigned char* iv);
void load_passwords_from_binary(PasswordNode** head, const char* filepath, const unsigned char* key,  unsigned char* iv);
void new_password_node(PasswordNode **head, const char* file_path, const unsigned char* key, const unsigned char* iv);
char* prompt_domain();
char *strptime(const char *buf, const char *format, struct tm *tm); // I don't know why but I needed to declare manually this function to transform a string to a tm struct.
int calculate_days_between_two_dates(struct tm date_modification);
#endif //PASSWORD_MANAGER_H
