#include <stdlib.h>

void print_char(const u_int8_t *msg, size_t msg_len) {
    for (size_t i = 0; i < msg_len; i++) {
        printf("%c", msg[i]);
    }
    printf("\n");
}
void print_hex(const u_int8_t *msg, size_t msg_len) {
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02x", msg[i]);
    }
    printf("\n");
}