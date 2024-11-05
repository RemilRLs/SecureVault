// Connection management using the master password.

#include "auth.h"

/**
* Construct the path of the master password file depending on the username.
*
* @param username The username of the user
* @param file_path The buffer where the file path will be stored
*/
void generate_master_password_file_path(const char *username, char* file_path) {
    // So it is like a printf but instead of printing it will store the result in the file_path variable so a buffer.
    // https://cplusplus.com/reference/cstdio/snprintf/

    snprintf(file_path, MASTER_PASSWORD_SIZE, "%s%s.gpg", MASTER_PASSWORD_FILE_PATH_PREFIX, username);
}

void generate_password_file_path(const char *username, char* file_path) {
    snprintf(file_path, FILE_PATH_SIZE, "%s%s.gpg", PASSWORD_MANAGER_PATH_PREFIX, username);
}

int manage_user_session(char *authenticated_username, unsigned char *key) {
    char username[USERNAME_SIZE];
    char file_path[FILE_PATH_SIZE];

    printf("[?] - Enter your username: ");
    fgets(username, USERNAME_SIZE, stdin);
    username[strcspn(username, "\n")] = 0;


    generate_master_password_file_path(username, file_path);

    FILE* master_passwd_file = open_file(file_path, "rb"); // rb because I want to check if the user already exist or not.

    // I check if the user already exist
    if(master_passwd_file == NULL) {
        printf("[!] - No master password found for %s.\n", username);
        create_master_password(username);
    } else {
        printf("[+] - Master password found for %s.\n", username);
        close_file(master_passwd_file);
    }


    char passwd[MASTER_PASSWORD_SIZE];
    printf("[?] - Enter your master password: ");
    fgets(passwd, MASTER_PASSWORD_SIZE, stdin);
    passwd[strcspn(passwd, "\n")] = 0;

    if(verify_master_password(username, passwd, key)) {
        printf("[+] - Master password is correct.\n");
        printf("[+] - Welcome %s.\n", username);
        strncpy(authenticated_username, username, USERNAME_SIZE); // I need to follow the user action.
        return 1;
    } else {
        printf("[!] - Master password is incorrect.\n");
        return 0;
    }


}

/**
* Create a master password for a user if that one does not exist. That one will be stored in a file.
*
* @param username The username of the user
*/
void create_master_password(const char *username) {
    // Method allowing the creation of a master password during the user first connection.
    char passwd[MASTER_PASSWORD_SIZE];
    char passwd_confirm[MASTER_PASSWORD_SIZE];
    char file_path[FILE_PATH_SIZE];

    generate_master_password_file_path(username, file_path);

    printf("[?] - Type your new master password: ");
    fgets(passwd, MASTER_PASSWORD_SIZE, stdin);
    passwd[strcspn(passwd, "\n")] = 0;

    printf("[?] - Confirm your new master password: ");
    fgets(passwd_confirm, MASTER_PASSWORD_SIZE, stdin);
    passwd_confirm[strcspn(passwd_confirm, "\n")] = 0;

    if (strcmp(passwd, passwd_confirm) != 0) {
        printf("[!] - Passwords do not match.\n");
        return;
    }

    // The two passwords match, we can now encrypt it in SHA1 then store it in a file that I make in './data/master_passwd.gpg'

    // Hash master password in SHA1.

    unsigned char hash[SHA1_HASH_SIZE];
    unsigned int hash_size;
    sha1_hash(passwd, strlen(passwd), hash, &hash_size);

    FILE *master_passwd_file = open_file(file_path, "wb");

    if (master_passwd_file == NULL) {
        printf("[!] - Error while creating the master password file.\n");
        return;
    }

    if (fwrite(hash, 1, hash_size, master_passwd_file) != hash_size) {
        printf("[!] - Error while writing to the master password file.\n");
    } else {
        printf("[+] - Master password has been hashed and stored securely.\n");
    }

    close_file(master_passwd_file);
}

/**
* Verify if the master password is correct for a user. I check if the hash of the password is the same as the one stored in the file.
* If it is the case, I store the hash in the key buffer.
*
* @param username The username of the user
* @param passwd The password to verify
* @param key The buffer where the hash will be stored and used to encrypt/decrypt the password manager file if that one exist of course :)
*/
int verify_master_password(const char* username, const char *passwd, unsigned char *key) {
    // Method allowing to check if the master password is correct.
    char file_path[FILE_PATH_SIZE];
    generate_master_password_file_path(username, file_path);

    unsigned char input_hash[SHA1_HASH_SIZE];
    unsigned int input_hash_size;
    sha1_hash(passwd, strlen(passwd), input_hash, &input_hash_size);

    FILE *master_passwd_file = open_file(file_path, "rb");
    if (master_passwd_file == NULL) {
        printf("[!] - Error opening master password file for %s.\n", username);
        return 0;
    }

    unsigned char stored_hash[SHA1_HASH_SIZE]; // I want the hash stored inside the file of the user.

    if(fread(stored_hash, 1, SHA1_HASH_SIZE, master_passwd_file) != SHA1_HASH_SIZE){
        printf("[!] - Error while reading the master password file.\n");
        close_file(master_passwd_file);
        return 0;
    }

    // Now I need to check if the hask are the same if I compare both of the.

    if(memcmp(input_hash, stored_hash, SHA1_HASH_SIZE) == 0){
        memcpy(key, input_hash, KEY_SIZE); // I store the hash in the key buffer this one will be used to encrypt/decrypt the password manager file.
        close_file(master_passwd_file);
        return 1;
    } else {
        printf("[-] - Password verification failed.\n");
        close_file(master_passwd_file);
        return 0;
    }
}

/**
* Check if a master password exists for a user so if that one already have a password manager.
*
* @param username The username of the user
* @return 0 if the user does not have a master password, 1 otherwise (no need to create a new one)
*/
int check_if_master_password_exists(const char *username) {
    // Method allowing to check if an user have already a password manager.
    char file_path[MASTER_PASSWORD_SIZE];
    generate_master_password_file_path(username, file_path);

    FILE *master_passwd_file = open_file(file_path, "rb");

    if (master_passwd_file == NULL) {
        printf("[!] - No master password found for %s.\n", username);
        create_master_password(username);
        return 0;
    } else {
        printf("[+] - Master password found for %s.\n", username);
        close_file(master_passwd_file);
        return 1;
    }
}




