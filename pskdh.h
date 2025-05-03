#ifndef PSKDH
#define PSKDH

unsigned char *hkdf(unsigned char *secret);
void psk_dh(const char *psk, unsigned char *out); 
void handleErrors();

#endif 
