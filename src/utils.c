#include <stdio.h>
// Various function allowing for example the generation of a random password

/**
* Open a file
*
* @param filename The name of the file to open
* @param accessMode The mode to open the file
* @return A pointer to the file
*/
FILE* open_file(const char * filename, const char * accessMode){
    // Function to open a file and return a pointer to it.
    FILE *fp = fopen(filename, accessMode);

    if(fp == NULL){
        fprintf(stderr, "[X] - Cannot open the file\n");
        return NULL;
    }
    return fp;
}


/**
* Close a file
*
* @param file The file to close
* @return 0 if the file is closed, -1 otherwise (error)
*/
int close_file(FILE* file) {
    // Function to close a file.
    if (fclose(file) == EOF) {
        fprintf(stderr, "[X] - Cannot close file\n");
        return -1;
    }
    return 0;
}

/**
* Get the size of a file
*
* @param filename The name of the file
* @return The size of the file
*/
long get_size_file(const char* filename) {
    // Function to get the size of a file.
    FILE *file = open_file(filename, "rb");

    if (file == NULL) {
        fprintf(stderr, "[X] - Cannot open the file\n");
        return -1;
    }

    fseek(file, 0, SEEK_END); // I go to the end of the file with indicator SEEK_END.

    return ftell(file);
}