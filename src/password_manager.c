// Allows you to manage the password manager, for example adding/modifying/deleting a password and other information

#include "password_manager.h"

void setup_user_password_file(const char* authenticated_username, unsigned char* iv) {
    char file_path[FILE_PATH_SIZE];
    generate_password_file_path(authenticated_username, file_path);

    FILE* file = open_file(file_path, "rb");

    if (file == NULL) {
        printf("[!] - No password manager file found for user : %s.\n", authenticated_username);

        printf("[*] - Creating new password manager file for user : %s.\n", authenticated_username);

        if(RAND_bytes(iv, IV_SIZE) != 1) {
            fprintf(stderr, "[X] - Error generating IV.\n");
            return;
        }

        file = open_file(file_path, "wb");
        if (file == NULL) {
            fprintf(stderr, "[X] - Error creating password manage");
            close_file(file);
            return;
        }

        if(fwrite(iv, sizeof(unsigned char), IV_SIZE, file) != IV_SIZE) {
            fprintf(stderr, "[X] - Error writing IV to file.\n");
            close_file(file);
            return;
        }

        printf("[DEBUG] - Position après IV: %ld\n", ftell(file));

        size_t plain_text_size = 0;

        if(fwrite(&plain_text_size, sizeof(size_t), 1, file) != 1) {
            fprintf(stderr, "[X] - Error writing size of plaintext to file.\n");
            close_file(file);
            return;
        }

        printf("[DEBUG] - Position après taille plain_text_size: %ld\n", ftell(file));
    } else {
          printf("[*] - Password manager file found for user : %s.\n", authenticated_username);

            if(fread(iv, 1, IV_SIZE, file) != IV_SIZE) {
                fprintf(stderr, "[X] - Error reading IV from file.\n");
                close_file(file);
                return;
            }
    }

    close_file(file);
}

PasswordNode* create_password_node(PasswordNode* head, const char* domain, const char* login, const char* password, const char* comment) {
    PasswordNode* new_node = (PasswordNode*)malloc(sizeof(PasswordNode));
    if (new_node == NULL) {
        printf("[!] - Error allocating memory for new password node.\n");
        return NULL;
    }
    new_node->id = get_id_number(head);
    strncpy(new_node->domain, domain, DOMAIN_SIZE);
    strncpy(new_node->login, login, LOGIN_SIZE);
    strncpy(new_node->password, password, PASSWORD_SIZE);
    strncpy(new_node->comment, comment, COMMENT_SIZE);

    time_t now = time(NULL);
    new_node->dateAdded = *localtime(&now);
    new_node->dateEdit = *localtime(&now);

    new_node->next = NULL;

    return new_node;
}

void add_password(PasswordNode** head, const char* domain, const char* login, const char* password, const char* comment) {
    PasswordNode* new_node = create_password_node(*head, domain, login, password, comment);
    if (new_node == NULL) {
        return;
    }

    if (*head == NULL) {
        *head = new_node;
        return;
    }

    PasswordNode* current = *head;

    // I'm going to the end of the chained link to put another passwd.
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}

// I need that to keep the date of the password when I add it/load it.
void add_password_with_dates(PasswordNode** head, const char* domain, const char* login, const char* password, const char* comment, struct tm dateAdded, struct tm dateEdit) {
    PasswordNode* new_node = (PasswordNode*)malloc(sizeof(PasswordNode));

    if (new_node == NULL) {
        fprintf(stderr, "[!] - Error allocating memory for new password node.\n");
        return;
    }

    new_node->id = get_id_number(*head);
    strncpy(new_node->domain, domain, DOMAIN_SIZE);
    strncpy(new_node->login, login, LOGIN_SIZE);
    strncpy(new_node->password, password, PASSWORD_SIZE);
    strncpy(new_node->comment, comment, COMMENT_SIZE);
    new_node->dateAdded = dateAdded;
    new_node->dateEdit = dateEdit;
    new_node->next = NULL;

    if (*head == NULL) {
        *head = new_node;
        return;
    }

    PasswordNode* current = *head;

    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}


void display_passwords(const PasswordNode* head) {
    if (head == NULL) {
        fprintf(stderr, "[!] - No password to display.\n");
        return;
    }

    const PasswordNode* current = head;

    while(current != NULL) {
        // https://koor.fr/C/ctime/strftime.wp
        char dateAdded[80];
        char dateEdit[80];

        printf("[+] - ID: %d\n", current->id);
        printf("[+] - Domain: %s\n", current->domain);
        printf("[+] - Login: %s\n", current->login);
        printf("[+] - Password: %s\n", current->password);
        printf("[+] - Comment: %s\n", current->comment);

        strftime(dateAdded, sizeof(dateAdded), "%Y-%m-%d %H:%M:%S", &current->dateAdded);
        strftime(dateEdit, sizeof(dateAdded), "%Y-%m-%d %H:%M:%S", &current->dateEdit);
        printf("[+] - Date Added: %s\n", dateAdded);
        printf("[+] - Date Edit: %s\n", dateEdit);

        printf("\n");

        current = current->next;
    }
}

// Method to print a specific node.
void display_specific_node(PasswordNode* node){
    char dateAdded[80];
    char dateEdit[80];

    printf("[+] - ID: %d\n", node->id);
    printf("[+] - Domain: %s\n", node->domain);
    printf("[+] - Login: %s\n", node->login);
    printf("[+] - Password: %s\n", node->password);
    printf("[+] - Comment: %s\n", node->comment);

    strftime(dateAdded, sizeof(dateAdded), "%Y-%m-%d %H:%M:%S", &node->dateAdded);
    strftime(dateEdit, sizeof(dateAdded), "%Y-%m-%d %H:%M:%S", &node->dateEdit);
    printf("[+] - Date Added: %s\n", dateAdded);
    printf("[+] - Date Edit: %s\n", dateEdit);

}

void delete_password(PasswordNode** head) {

    printf("[?] - Delete by 'id' or 'domain': ");
    char choice[10];
    fgets(choice, sizeof(choice), stdin);
    choice[strcspn(choice, "\n")] = 0;

    if(strcmp(choice, "id") == 0) { // Search by ID then delete.
        unsigned int id;
        printf("[?] - Enter the id of the password to delete: ");
        scanf("%u", &id);
        getchar();

        PasswordNode *current = *head;
        PasswordNode *previous = NULL;

        while (current != NULL) {
            if (current->id == id) {
                if (previous == NULL) { // We are at the fisst element so the head so I remove the head
                    *head = current->next;
                } else {
                    previous->next = current->next;
                }
                free(current);
                printf("[+] - Password with ID %u deleted successfully.\n", id);
                return;
            }
            previous = current;
            current = current->next;
        }

        printf("[X] - No password found with ID %u.\n", id);

    } else if (strcmp(choice, "domain") == 0) { // Search by domain then delete.
        char *domain = prompt_domain();
        PasswordNode *current = *head;
        PasswordNode *previous = NULL;

        while (current != NULL) {
            if (strcmp(current->domain, domain) == 0) {
                if (previous == NULL) {
                    *head = current->next;
                } else {
                    previous->next = current->next;
                }
                free(current);
                printf("[+] - Password for domain '%s' deleted successfully.\n", domain);
                return;
            }
            previous = current;
            current = current->next;
    }
    printf("[X] - No password found with domain '%s'.\n", domain);

    } else {
        printf("[X] - Invalid choice.\n");
    }
}

// Method to delete a node inside the password manager list of a user.
void free_password_list(PasswordNode* head) {
    PasswordNode* current = head;

    while (current != NULL) {
      PasswordNode *temp = current;
      current = current->next;
      free(temp);
    }
}

void save_passwords_to_binary(PasswordNode* head, const char* filepath, const unsigned char* key, const unsigned char* iv) {

    size_t bufferSize = PLAIN_TEXT_BUFFER_SIZE;
    unsigned char* plaintext_buffer = (unsigned char*)malloc(bufferSize);
    if (plaintext_buffer == NULL) {
        fprintf(stderr, "[X] - Error allocating memory for plaintext buffer.\n");
        return;
    }

    size_t offset = 0;

    PasswordNode* current = head;

    while(current != NULL) {
        size_t nodeDataSize = sizeof(unsigned int) + DOMAIN_SIZE + LOGIN_SIZE + PASSWORD_SIZE + COMMENT_SIZE + sizeof(struct tm) * 2;
        size_t requiredSize = offset + nodeDataSize;

        if (requiredSize > bufferSize) {
            bufferSize *= 2;
            unsigned char* newBuffer = (unsigned char*)realloc(plaintext_buffer, bufferSize);

            if (newBuffer == NULL) {
                fprintf(stderr, "[X] - Error reallocating memory for plaintext buffer.\n");
                goto cleanup;
            }
            plaintext_buffer = newBuffer;
        }

        memcpy(plaintext_buffer + offset, &current->id, sizeof(unsigned int));
        offset += sizeof(unsigned int);

        memcpy(plaintext_buffer + offset, current->domain, DOMAIN_SIZE);
        offset += DOMAIN_SIZE;

        memcpy(plaintext_buffer + offset, current->login, LOGIN_SIZE);
        offset += LOGIN_SIZE;

        memcpy(plaintext_buffer + offset, current->password, PASSWORD_SIZE);
        offset += PASSWORD_SIZE;

        memcpy(plaintext_buffer + offset, current->comment, COMMENT_SIZE);
        offset += COMMENT_SIZE;

        memcpy(plaintext_buffer + offset, &current->dateAdded, sizeof(struct tm));
        offset += sizeof(struct tm);

        memcpy(plaintext_buffer + offset, &current->dateEdit, sizeof(struct tm));
        offset += sizeof(struct tm);

        current = current->next;
    }

    /*
        I need EVP_MAX_BLOCK_LENGTH to have some padding imagine if my password is 14 bytes long
        It's not going to work if I don't but that and can generator error because AES encrypt with block of 16 bytes
        and I have 14 bytes so I need to add 2 bytes to have 16 bytes with EVP_MAX_BLOCK_LENGTH that is just padding.
        I know that EVP_EncryptFinal_ex is going to add the necessary padding but imagine if it go more than my PASSWORD_SIZE Buffer
        I will have a buffer overflow so I need to add this padding manualy just to be sure.
     */

    size_t cipherTextBufferSize = bufferSize + EVP_MAX_BLOCK_LENGTH;
    unsigned char* ciphertext_buffer = (unsigned char*)malloc(cipherTextBufferSize);

    if (ciphertext_buffer == NULL) {
        fprintf(stderr, "[X] - Error allocating memory for ciphertext buffer.\n");
        goto cleanup;
    }

    int ciphertext_len = aes_encrypt(plaintext_buffer, offset, (unsigned char*)key, (unsigned char*)iv, ciphertext_buffer);

    if (ciphertext_len == -1) {
        fprintf(stderr, "[X] - Error encrypting data.\n");
        goto cleanup;
    }

    FILE* file = open_file(filepath, "rb+"); // rb+

    if(file == NULL) {
        fprintf(stderr, "[X] - Error opening file for writing encrypted data.\n");
        goto cleanup;
    }

    fseek(file, IV_SIZE, SEEK_SET);

    if (fwrite(&offset, sizeof(size_t), 1, file) != 1) {
        fprintf(stderr, "[X] - Error writing plain_text_size to the file.\n");
        goto cleanup;
    }

    if(fwrite(ciphertext_buffer, 1, ciphertext_len, file) != (size_t)ciphertext_len) {
        fprintf(stderr, "[X] - Error writing encrypted data to file.\n");
        goto cleanup;
    } else {
        printf("[+] - Encrypted data written to file.\n");
    }
    /*
        https://linux.die.net/man/2/ftruncate
        My saviooooooor, I think I'm racking my brains too much

        So what I do I go at the end of the file so at the end after I put the IV_SIZE, plaintext size and ciphertext size
        and I truncate so I ajust the size of my file about a specific value that is IV_SIZE + sizeof(size_t) + ciphertext_len
        at the end I have only that so I delete (truncate) the rest of the file.

        That was soooo useful when I update my data !

     */
    if (ftruncate(fileno(file), IV_SIZE + sizeof(size_t) + ciphertext_len) != 0) {
        fprintf(stderr, "[X] - Error truncating file.\n");
    }
cleanup:
    close_file(file);
    free(plaintext_buffer);
    free(ciphertext_buffer);
}


void load_passwords_from_binary(PasswordNode** head, const char* filepath, const unsigned char* key, unsigned char* iv) {
    size_t plain_text_size = 0;
    FILE *file = open_file(filepath, "rb");

    if (file == NULL) {
        fprintf(stderr, "[X] - Error opening file for reading encrypted data.\n");
        return;
    }

    // I'm reading the IV first.
    if (fread(iv, 1, IV_SIZE, file) != IV_SIZE) {
        fprintf(stderr, "[X] - Error reading IV from file.\n");
        close_file(file);
        return;
    }


    if (fread(&plain_text_size, sizeof(size_t), 1, file) != 1) { // For plaintext size.
        fprintf(stderr, "[X] - Error reading size of plaintext from file.\n");
        close_file(file);
        return;
    }
    printf("[DEBUG] - Plain text size lu : %zu\n", plain_text_size);

    if (plain_text_size == 0) {
        printf("[!] - No password to load.\n");
        close_file(file);
        return;
    }

    // I need to get the size of the file to know how many bytes I need to read.
    long file_size = get_size_file(filepath);
    if (file_size == -1) {
        fprintf(stderr, "[X] - Error getting file size.\n");
        close_file(file);
        return;
    }


    size_t ciphertext_size = file_size - IV_SIZE - sizeof(size_t); // I do this because I already read the IV and plaintext and I don't need it anymore. I do the same for the size of the plaintext.
    if (ciphertext_size <= 0) {
        fprintf(stderr, "[X] - Ciphertext size invalid or no data present.\n");
        close_file(file);
        return;
    }

    unsigned char* ciphertext_buffer = (unsigned char*)malloc(ciphertext_size);
    unsigned char* plaintext_buffer = (unsigned char*)malloc(plain_text_size);

    if (plaintext_buffer == NULL || ciphertext_buffer == NULL) {
        fprintf(stderr, "[X] - Error allocating memory for buffers.\n");
        free(plaintext_buffer);
        free(ciphertext_buffer);
        close_file(file);
        return;
    }


    if (fread(ciphertext_buffer, 1, ciphertext_size, file) != ciphertext_size) {
        fprintf(stderr, "[X] - Error reading encrypted data from file.\n");
        free(ciphertext_buffer);
        free(plaintext_buffer);
        close_file(file);
        return;
    }

    close_file(file);

    // Print the key
    printf("[DEBUG] - Key: ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }

    // Print IV
    printf("\n[DEBUG] - IV: ");
    for (int i = 0; i < IV_SIZE; i++) {
        printf("%02x", iv[i]);
    }

    int decrypted_size = aes_decrypt(ciphertext_buffer, ciphertext_size, (unsigned char*)key, iv, plaintext_buffer);
    if (decrypted_size == -1) {
        fprintf(stderr, "[X] - Error decrypting data.\n");
        free(ciphertext_buffer);
        free(plaintext_buffer);
        return;
    }

    int offset = 0;
    while ((size_t)offset < plain_text_size) {
        unsigned int id;
        char domain[DOMAIN_SIZE];
        char login[LOGIN_SIZE];
        char password[PASSWORD_SIZE];
        char comment[COMMENT_SIZE];
        struct tm dateAdded;
        struct tm dateEdit;

        memcpy(&id, plaintext_buffer + offset, sizeof(unsigned int));
        offset += sizeof(unsigned int);

        memcpy(domain, plaintext_buffer + offset, DOMAIN_SIZE);
        offset += DOMAIN_SIZE;

        memcpy(login, plaintext_buffer + offset, LOGIN_SIZE);
        offset += LOGIN_SIZE;

        memcpy(password, plaintext_buffer + offset, PASSWORD_SIZE);
        offset += PASSWORD_SIZE;

        memcpy(comment, plaintext_buffer + offset, COMMENT_SIZE);
        offset += COMMENT_SIZE;

        memcpy(&dateAdded, plaintext_buffer + offset, sizeof(struct tm));
        offset += sizeof(struct tm);

        memcpy(&dateEdit, plaintext_buffer + offset, sizeof(struct tm));
        offset += sizeof(struct tm);

        // Check expiration date of a password

        int days = calculate_days_between_two_dates(dateEdit);
        if (days >= 90) { // I notify the user.
            printf("[!] - Password for domain %s and login %s has expired please modify your password.\n", domain, login);
        }

        add_password_with_dates(head, domain, login, password, comment, dateAdded, dateEdit);
    }

    free(ciphertext_buffer);
    free(plaintext_buffer);

    printf("[+] - Password list decrypted and loaded successfully.\n");
}


// Method to get ID.
unsigned int get_id_number(PasswordNode *head) {
    unsigned int id;
    int count = 1;

    while(head != NULL) {
        count++;
        head = head->next;
    }

    id = count;

    return id;
}

char* generate_aleatory_passwd(){
    // https://www.ibm.com/docs/fr/i/7.5?topic=functions-sscanf-read-data

    char special_characters[] = "!@#$%^&*()_+";
    char numbers[] = "0123456789";
    char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char choice_user_selection[75] = "";

    int length;
    char input[5];
    int include_uppercase, include_lowercase, include_numbers, include_special;

    printf("[?] - Enter the length of the password: ");
    fgets(input,sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // I remove the \n
    sscanf(input, "%d", &length); // I extract the data with sscanf and put it inside the length variable.

    if (length < 12) {
        fprintf(stderr, "[X] - Password length must be at least 12 characters\n");
        return NULL;
    }

    printf("[?] - Include uppercase characters (1 for yes, 0 for no): ");
    fgets(input,sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    sscanf(input, "%d", &include_uppercase);

    printf("[?] - Include lowercase characters (1 for yes, 0 for no): ");
    fgets(input,sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    sscanf(input, "%d", &include_lowercase);

    printf("[?] - Include numbers (1 for yes, 0 for no): ");
    fgets(input,sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    sscanf(input, "%d", &include_numbers);

    printf("[?] - Include special characters (1 for yes, 0 for no): ");
    fgets(input,sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    sscanf(input, "%d", &include_special);

    if (include_uppercase == 0 && include_lowercase == 0 && include_numbers == 0 && include_special == 0) {
        fprintf(stderr, "[X] - At least one character type must be included in the password\n");
        return NULL;
    }

    if (include_uppercase == 1) {
        strcat(choice_user_selection, uppercase);
    }
    if (include_lowercase == 1) {
        strcat(choice_user_selection, lowercase);
    }
    if (include_numbers == 1) {
        strcat(choice_user_selection, numbers);
    }
    if (include_special == 1) {
        strcat(choice_user_selection, special_characters);
    }

    char* password = (char*)malloc((length + 1) * sizeof(char));
    if (password == NULL) {
        fprintf(stderr, "[X] - Error allocating memory for password\n");
        return NULL;
    }

    srand(time(NULL));

    for (int i = 0; i < length; i++) {
        password[i] = choice_user_selection[rand() % strlen(choice_user_selection)]; // I selecte random character link to the user selection.
    }

    password[length] = '\0';

    return password;
}

void search_node_password(PasswordNode* head) {
    PasswordNode* result_node = NULL;

    printf("[?] - Do you want to search by 'id', 'domain', 'login': ");

    char search_by[10];
    fgets(search_by, sizeof(search_by), stdin);
    search_by[strcspn(search_by, "\n")] = 0;

    // :( I was thinking that we can take strings with switch case but no...

    if(strcmp(search_by, "id") == 0) {
        unsigned int id;
        printf("[?] - Enter the ID of the password: ");
        fgets(search_by, sizeof(search_by), stdin);
        search_by[strcspn(search_by, "\n")] = 0;
        sscanf(search_by, "%d", &id);

        result_node = search_by_id(head, id);
        display_specific_node(result_node);
    } else if(strcmp(search_by, "domain") == 0) {
        char domain[DOMAIN_SIZE];
        printf("[?] - Enter the domain of the password: ");
        fgets(domain, sizeof(domain), stdin);
        domain[strcspn(domain, "\n")] = 0;

        result_node = search_by_domain(head, domain);
        display_specific_node(result_node);
    } else if(strcmp(search_by, "login") == 0) {
        char login[LOGIN_SIZE];
        printf("[?] - Enter the login of the password: ");
        fgets(login, sizeof(login), stdin);
        login[strcspn(login, "\n")] = 0;

        result_node = search_by_login(head, login);
        display_specific_node(result_node);
    } else {
        fprintf(stderr, "[X] - Cannot find method.\n");
    }

    if (result_node == NULL){
        printf("[X] - Cannot find any node.\n");
    }

}

// Method to search by id.
PasswordNode* search_by_id(PasswordNode* head, unsigned int id){
    PasswordNode* current = head;

    while(current != NULL) {
        if(current->id == id) {
            display_specific_node(current);
            return current;
        }

        current = current->next;
    }

    printf("[X] - Cannot find any node with id %d\n", id);
    return NULL;
}

// Method to search by domain.
PasswordNode* search_by_domain(PasswordNode* head, const char* domain){
    PasswordNode* current = head;

    while(current != NULL) {
        if(strcmp(current->domain, domain) == 0) {
            return current;
        }

        current = current->next;
    }

    printf("[X] - Cannot find any node with domain %s\n", domain);
    return NULL;
}

// Method to search by login.
PasswordNode* search_by_login(PasswordNode* head, const char* login){
    PasswordNode* current = head;

    while(current != NULL) {
        if(strcmp(current->login, login) == 0) {
            display_specific_node(current);
            return current;
        }

        current = current->next;
    }

    printf("[X] - Cannot find any node with login %s\n", login);
    return NULL;
}

// Method to modify a node by id, domain or login.
void modify_node(PasswordNode *head){
    PasswordNode* result_node = NULL;
    printf("[?] - Do you want to modify by 'id', 'domain', 'login': ");

    char search_by[10];
    fgets(search_by, sizeof(search_by), stdin);
    search_by[strcspn(search_by, "\n")] = 0;

    if(strcmp(search_by, "id") == 0) {
        unsigned int id;
        printf("[?] - Enter the ID of the node that you want modify: ");
        fgets(search_by, sizeof(search_by), stdin);
        search_by[strcspn(search_by, "\n")] = 0;
        sscanf(search_by, "%d", &id);

        result_node = search_by_id(head, id);

    } else if(strcmp(search_by, "domain") == 0) {
        char domain[DOMAIN_SIZE];
        printf("[?] - Enter the domain of the node that you want modify: ");
        fgets(domain, sizeof(domain), stdin);
        domain[strcspn(domain, "\n")] = 0;

        result_node = search_by_domain(head, domain);
    } else if(strcmp(search_by, "login") == 0) {
        char login[LOGIN_SIZE];
        printf("[?] - Enter the login of the node that you want modify: ");
        fgets(login, sizeof(login), stdin);
        login[strcspn(login, "\n")] = 0;

        result_node = search_by_login(head, login);
    } else {
        fprintf(stderr, "[X] - Cannot find method.\n");
    }

    if(result_node == NULL) {
        printf("[X] - Cannot find any node to modify.\n");
        return;
    }

    printf("[+] - Node found, you can now modify it.\n");

    printf("[?] - New domain (leave empty to keep the same): ");
    char new_domain[DOMAIN_SIZE];
    fgets(new_domain, sizeof(new_domain), stdin);
    new_domain[strcspn(new_domain, "\n")] = 0;
    if(strlen(new_domain) > 0) {
        strncpy(result_node->domain, new_domain, DOMAIN_SIZE);
    }

    printf("[?] - New login (leave empty to keep the same): ");
    char new_login[LOGIN_SIZE];
    fgets(new_login, sizeof(new_login), stdin);
    new_login[strcspn(new_login, "\n")] = 0;
    if(strlen(new_login) > 0) {
        strncpy(result_node->login, new_login, LOGIN_SIZE);
    }

    printf("[?] - Do you want an aleatory password (1 for yes, 0 for no): ");
    char choice[5];
    fgets(choice, sizeof(choice), stdin);
    choice[strcspn(choice, "\n")] = 0;

    char new_password[PASSWORD_SIZE] = "";
    int password_updated = 0;

    if (strcmp(choice, "1") == 0) {
        char* generated_password = generate_aleatory_passwd();
        if (generated_password != NULL) {
            strncpy(result_node->password, generated_password, PASSWORD_SIZE);
            free(generated_password);
            password_updated = 1;
        }
    } else {
        printf("[?] - New password (leave empty to keep the same): ");
        fgets(new_password, sizeof(new_password), stdin);
        new_password[strcspn(new_password, "\n")] = 0;
        if (strlen(new_password) > 0) {
            strncpy(result_node->password, new_password, PASSWORD_SIZE);
            password_updated = 1;
        }
    }

    printf("[?] - New comment (leave empty to keep the same): ");
    char new_comment[COMMENT_SIZE];
    fgets(new_comment, sizeof(new_comment), stdin);
    new_comment[strcspn(new_comment, "\n")] = 0;
    if(strlen(new_comment) > 0) {
        strncpy(result_node->comment, new_comment, COMMENT_SIZE);
    }

    if (password_updated || strlen(new_comment) > 0 || strlen(new_domain) > 0 || strlen(new_login) > 0) {
        time_t now = time(NULL);
        result_node->dateEdit = *localtime(&now);
        printf("[+] - Entry updated successfully.\n");
    } else {
        printf("[!] - No changes were made.\n");
    }
}

// Method to export the password manager list to a CSV file.
void export_passwordnode_csv(PasswordNode *head, const char* authenticated_username) {
    PasswordNode* current = head;

    char file_path_refacto[FILE_PATH_SIZE];

    snprintf(file_path_refacto, FILE_PATH_SIZE, "%s%s.csv", CSV_EXPORT_FILE_PREFIX, authenticated_username);
	printf("[DEBUG] - Final file path: %s\n", file_path_refacto);


    FILE *file = open_file(file_path_refacto, "w");

    if (file == NULL) {
        fprintf(stderr, "[X] - Error opening file for writing CSV data.\n");
        perror("[X] - fopen");
        return;
    }


    fprintf(file, "ID,Domaine,Login,Mot de passe,Commentaire,Added Date, Edit Date\n");

    while(current != NULL) {
        char dateAdded[80];
        char dateEdit[80];

        strftime(dateAdded, sizeof(dateAdded), "%Y-%m-%d %H:%M:%S", &current->dateAdded);
        strftime(dateEdit, sizeof(dateEdit), "%Y-%m-%d %H:%M:%S", &current->dateEdit);

        fprintf(file, "%d,%s,%s,%s,%s,%s,%s\n", current->id, current->domain, current->login, current->password, current->comment, dateAdded, dateEdit);

        current = current->next;

    }

    close_file(file);
    printf("[*] - List of Passwords exported in CSV\n\n");
}

void import_passwordnode_csv(PasswordNode **head, const char* authenticated_username){
    char file_path_refacto[FILE_PATH_SIZE];
    char line[2048];

    snprintf(file_path_refacto, FILE_PATH_SIZE, "%s%s.csv", CSV_EXPORT_FILE_PREFIX, authenticated_username);

    FILE* file = fopen(file_path_refacto, "r");
    if (file == NULL) {
        fprintf(stderr, "[X] - Error opening CSV file for import.\n");
        return;
    }

    // I do this because I don't want the first line.

    if (fgets(line, sizeof(line), file) == NULL) {
        fprintf(stderr, "[X] - Error reading first line of CSV file.\n");
        fclose(file);
        return;
    }

    // Here what I do is that I read every line of the CSV file.
    while (fgets(line, sizeof(line), file) != NULL) {
       unsigned int id;
       char domain[DOMAIN_SIZE];
       char login[LOGIN_SIZE];
       char password[PASSWORD_SIZE];
       char comment[COMMENT_SIZE];

       char dateAddedStr[80], dateEditStr[80];
       struct tm dateAdded;
       struct tm dateEdit;

       // I'm going to read each column until I get met a ',' and I put the data inside the variables.
       // The last one %s is for the last column so there is no ',' at the end so I read until the end of the line.

        if (sscanf(line, "%u,%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", &id, domain, login, password, comment, dateAddedStr, dateEditStr) != 7) {
            fprintf(stderr, "[X] - Error reading line from CSV file.\n");
            continue;
        }

       // https://www.ibm.com/docs/fr/i/7.5?topic=functions-strptime-convert-string-datetime

       strptime(dateAddedStr, "%Y-%m-%d %H:%M:%S", &dateAdded);
       strptime(dateEditStr, "%Y-%m-%d %H:%M:%S", &dateEdit);

       add_password_with_dates(head, domain, login, password, comment, dateAdded, dateEdit);
    }

    close_file(file);

}

void new_password_node(PasswordNode **head, const char* file_path, const unsigned char* key, const unsigned char* iv) {
    char domain[DOMAIN_SIZE];
    char login[LOGIN_SIZE];
    char passwd[PASSWORD_SIZE];
    char comment[COMMENT_SIZE];

   printf("[*] - Enter the domain: ");
    fgets(domain, DOMAIN_SIZE, stdin);
    domain[strcspn(domain, "\n")] = 0;

    printf("[*] - Enter the login: ");
    fgets(login, LOGIN_SIZE, stdin);
    login[strcspn(login, "\n")] = 0;

    printf("[?] - Do you want an aleatory password (1 for yes, 0 for no): ");
    char choice[5];
    fgets(choice, sizeof(choice), stdin);
    choice[strcspn(choice, "\n")] = 0;


    if (strcmp(choice, "1") == 0) {
        char* generated_password = generate_aleatory_passwd();
        if (generated_password != NULL) {
            strncpy(passwd, generated_password, PASSWORD_SIZE);
            free(generated_password);
        } else {
            fprintf(stderr, "[X] - Error generating password.\n");
            return;
        }
    } else {
      while(1) {
        printf("[*] - Enter the password (at least 12 characters): ");
        fgets(passwd, PASSWORD_SIZE, stdin);
        passwd[strcspn(passwd, "\n")] = 0;

        if(strlen(passwd) < 12) {
        fprintf(stderr, "[X] - Password must be at least 12 characters.\n");
        } else {
            break; // Nice :)
        }
      }
    }

    printf("[*] - Enter the comment: ");
    fgets(comment, COMMENT_SIZE, stdin);
    comment[strcspn(comment, "\n")] = 0;

    add_password(head, domain, login, passwd, comment);
    printf("[+] - Password node added successfully.\n");

    save_passwords_to_binary(*head, file_path, key, iv);
}


int calculate_days_between_two_dates(struct tm date_modification) {
    time_t now = time(NULL);
    struct tm *current_date = localtime(&now);

    time_t date_modification_seconds = mktime(&date_modification);
    time_t current_date_seconds = mktime(current_date);

    double difference = difftime(current_date_seconds, date_modification_seconds);

    return difference / NUMBER_SECOND_IN_A_DAY;
}

char* prompt_domain() {
    static char domain[DOMAIN_SIZE];
    printf("[*] - Enter the domain: ");
    fgets(domain, DOMAIN_SIZE, stdin);
    domain[strcspn(domain, "\n")] = 0;

    return domain;
}
