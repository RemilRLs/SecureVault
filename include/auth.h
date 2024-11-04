// Connection management using the master password
#include <stdio.h>
#include <string.h>

#include "encryption.h"
#include "utils.h"


#ifndef AUTH_H
#define AUTH_H

#define MASTER_PASSWORD_FILE_PATH "data/master_passwd.gpg"
#define PASSWORD_MANAGER_PATH_PREFIX "data/password_manager/passwd_manager_user_"
#define MASTER_PASSWORD_SIZE 255
#define FILE_PATH_SIZE 255
#define MASTER_PASSWORD_FILE_PATH_PREFIX "data/master_passwd_"
#define SHA1_HASH_SIZE 20
#define USERNAME_SIZE 50
#define IV_SIZE 16
#define KEY_SIZE 16


void generate_master_password_file_path(const char *username, char *file_path);
void generate_password_file_path(const char *username, char* file_path);
void create_master_password(const char *username);
int check_master_password(const char *username);
int check_if_master_password_exists(const char *username);
int manage_user_session(char *authenticated_username, unsigned char *key);
int verify_master_password(const char* username, const char *passwd, unsigned char *key);


#endif //AUTH_H
