#include <stdio.h>
// Various function allowing for example the generation of a random password

#ifndef UTILS_H
#define UTILS_H

FILE* open_file(const char * filename, const char * accessMode);
int close_file(FILE* file);
long get_size_file(const char* filename);

#endif //UTILS_H
