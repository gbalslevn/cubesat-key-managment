
#ifndef PRINTUTIL
#define PRINTUTIL

#include <stdlib.h>
static int KEYSIZE;
void print_hex(const u_int8_t *msg, size_t msg_len);
void print_char(const u_int8_t *msg, size_t msg_len);

#endif