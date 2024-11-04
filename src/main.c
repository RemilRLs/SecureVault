#include "auth.h"
#include "password_manager.h"


void display_menu() {
    printf("\n--- Password Manager ---\n");
    printf("1. Add Password\n");
    printf("2. Delete Password\n");
    printf("3. Search Password\n");
    printf("4. Modify Password\n");
    printf("5. Display All Passwords\n");
    printf("6. Export Passwords to CSV\n");
    printf("7. Import Passwords from CSV\n");
    printf("8. Exit\n");
    printf("Choose an option: ");
}

int main(){
    char authenticated_username[USERNAME_SIZE] = ""; // I need to follow each action for each user.
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];

    if(!manage_user_session(authenticated_username, key)) { // Cannot login the user.
      printf("[X] - Exiting, wrong login...\n");
      return 0;
    }

    PasswordNode *head = NULL;
    int choice;
    char file_name[FILE_PATH_SIZE];

    generate_password_file_path(authenticated_username, file_name);

    setup_user_password_file(authenticated_username, iv);

    load_passwords_from_binary(&head, file_name, key, iv);

    printf("[+] - Welcome %s\n", authenticated_username);
    printf("[+] - Password Manager started\n");
    printf("[+] - Password Manager file: %s\n", file_name);

    while(1) {
        display_menu();
        scanf("%d", &choice);
        getchar();
        switch(choice) {
            case 1:
                new_password_node(&head, file_name, key, iv);
                break;
            case 2:
                delete_password(&head);
                save_passwords_to_binary(head, file_name, key, iv);
                break;
            case 3:
                search_node_password(head);
                break;
            case 4:
                modify_node(head);
                save_passwords_to_binary(head, file_name, key, iv);
                break;
            case 5:
                display_passwords(head);
                break;
            case 6:
                export_passwordnode_csv(head, authenticated_username);
                break;
            case 7:
                import_passwordnode_csv(&head, authenticated_username);
                save_passwords_to_binary(head, file_name, key, iv);
                break;
            case 8:
                save_passwords_to_binary(head, file_name, key, iv);
                free_password_list(head);
                printf("[*] - Exiting Password Manager\n");
                return 0;
        }


    }

    return 0;
}
