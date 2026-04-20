#include "NXs.h"
#include <unistd.h>
#include <limits.h>

// --- IO ---

void nx_print(const char *msg) {
    if (msg) {
        printf("%s", msg);
    }
}

void nx_println(const char *msg) {
    if (msg) {
        printf("%s\n", msg);
    } else {
        printf("\n");
    }
}

// --- File System ---

char* nx_read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = malloc(length + 1);
    if (buffer) {
        fread(buffer, 1, length, f);
        buffer[length] = '\0';
    }
    
    fclose(f);
    return buffer;
}

void nx_write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    
    if (content) {
        fprintf(f, "%s", content);
    }
    
    fclose(f);
}

// --- Process ---

void nx_exit(int code) {
    exit(code);
}

char* nx_cwd() {
    static char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        return cwd;
    } else {
        return NULL;
    }
}

// --- Porffor Bridge (ABI Compatibility) ---

typedef struct {
  double value;
  int type;
} porffor_res_t;

// Matches: function nx_print(msg)
porffor_res_t nx_print_abi(double nt, int ntt, double th, int tht, double msg, int msgt) {
    // In Porffor, string pointers are passed as f64 (ptr cast)
    // We assume msgt == 5 (String reference?) or similar. 
    // For this prototype, we just treat msg as a char* ptr cast to double.
    
    // Note: This is unsafe and depends on Porffor's memory model (usually linear memory).
    // If Porffor passes a pointer to the string data:
    const char* str = (const char*)((unsigned long)msg);
    nx_print(str);
    
    return (porffor_res_t){0, 0}; // void/undefined
}
