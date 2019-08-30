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
  BIGNUM *aux = BN_new();
  BIGNUM *p_1 = BN_new();
  BIGNUM *q_1 = BN_new();
  BIGNUM *two = BN_new();

  // phi_n = (p - 1) * (q - 1)
  BN_sub(p_1, p, BN_value_one());
  BN_sub(q_1, q, BN_value_one());
  BN_mul(aux, p_1, q_1, ctx);

  // d = ((2 * phi_n) + 1) / e
  BN_dec2bn(&two, "2");
  BN_mul(aux, aux, two, ctx);
  BN_add(aux, aux, BN_value_one());
  BN_div(aux, NULL, aux, e, ctx);
  
  BN_free(q_1);
  BN_free(p_1);
  BN_free(two);

  return aux;
}

int main() {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *m = BN_new();//BN_value_one
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