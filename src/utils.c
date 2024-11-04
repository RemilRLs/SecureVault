#include <stdio.h>
// Various function allowing for example the generation of a random password

// Function to open a file and return a pointer to it.
FILE* open_file(const char * filename, const char * accessMode){
    FILE *fp = fopen(filename, accessMode);

    if(fp == NULL){
        fprintf(stderr, "[X] - Cannot open the file\n");
        return NULL;
    }
    return fp;
}

// Function to close a file.

int close_file(FILE* file) {
    if (fclose(file) == EOF) {
        fprintf(stderr, "[X] - Cannot close file\n");
        return -1;
    }
    return 0;
}

// Function to get the size of a file.
long get_size_file(const char* filename) {
    FILE *file = open_file(filename, "rb");

    if (file == NULL) {
        fprintf(stderr, "[X] - Cannot open the file\n");
        return -1;
    }

    fseek(file, 0, SEEK_END); // I go to the end of the file with indicator SEEK_END.

    return ftell(file);
}