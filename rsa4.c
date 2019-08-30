/* bn_sample.c */
#include <openssl/bn.h>
#include <stdio.h>
#define NBITS 256

void printBN(char *msg, BIGNUM *a) {
  /* Use BN_bn2hex(a) for hex string
   * Use BN_bn2dec(a) for decimal string */
  char *number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *m1 = BN_new();
  BIGNUM *m2 = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *s1 = BN_new();
  BIGNUM *s2 = BN_new();

  // Assign a value from a hex number string
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_hex2bn(&e, "010001");
  // I owe you $2000
  BN_hex2bn(&m1, "49206f776520796f75202432303030");
  // I owe you $3000
  BN_hex2bn(&m2, "49206f776520796f75202433303030");

  // Sign messages with private key
  BN_mod_exp(s1, m1, d, n, ctx);
  BN_mod_exp(s2, m2, d, n, ctx);

  printBN("s1 =", s1);
  printBN("s2 =", s2);

  BN_CTX_free(ctx);

  return 0;
}
