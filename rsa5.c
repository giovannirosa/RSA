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
  BIGNUM *m_verify = BN_new();
  BIGNUM *m = BN_new();
  BIGNUM *s = BN_new();

  // Assign a value from a hex number string
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  // Launch a missile.
  BN_hex2bn(&m_verify, "4c61756e63682061206d697373696c652e");

  // Verify signature
  BN_mod_exp(m, s, e, n, ctx);

  printf("signature = %s\n", BN_cmp(m_verify, m) == 0 ? "CORRECT" : "WRONG");

  BN_CTX_free(ctx);

  return 0;
}