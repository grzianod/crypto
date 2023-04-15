#include <openssl/bn.h>
#include <openssl/err.h>

int main()
{

  BIGNUM *a=BN_new();
  BN_hex2bn(&a, "11111111111111111111111111111111");

  BIGNUM *b=BN_new();
  BN_hex2bn(&b, "22222222222222222222222222222222");

  BIGNUM *c=BN_new();
  BN_hex2bn(&c, "3333");

  BIGNUM *d=BN_new();
  BN_hex2bn(&d, "2341234123412341234");
  
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_add(a, a, b, d, ctx);
    BN_mod_exp(a, a, c, d, ctx);
    
    BN_print_fp(stdout, a);
  

  
  return 0;
}
