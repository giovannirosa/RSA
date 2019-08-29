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

BIGNUM *get_private_key(BIGNUM *p, BIGNUM *q, BIGNUM *e, BIGNUM *n,
                        BN_CTX *ctx) {
  BIGNUM *d = BN_dup(n);
  BN_sub(d, d, p);
  BN_sub(d, d, q);
  BN_add_word(d, 1);
  BN_mod_inverse(d, e, d, ctx);

  return d;
}

int main() {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *m = BN_new();
  BIGNUM *c = BN_new();

  // Assign a value from a hex number string
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");
  BN_mul(n, p, q, ctx);

  // Get Private Key
  BIGNUM *d = get_private_key(p, q, e, n, ctx);
  printBN("d = ", d);

  BN_CTX_free(ctx);

  return 0;
}