#ifndef NX_SYSTEM_H
#define NX_SYSTEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// TypeDefs matching Porffor's expectations (if any specific ones needed)
// For now, we expose C-standard types but aliased for clarity
typedef struct {
    char *data;
    size_t length;
} nx_string_t;

// Console / IO
void nx_print(const char *msg);
void nx_println(const char *msg);

// File System (Minimal)
char* nx_read_file(const char *path);
void nx_write_file(const char *path, const char *content);

// Process
void nx_exit(int code);
char* nx_cwd();

#endif // NX_SYSTEM_H
