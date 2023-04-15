#include <stdio.h>
#include <openssl/bn.h>

int main() {

    BIGNUM *bn1 = BN_new();

    BN_set_word(bn1, 12300000000000000000);
    printf("bn1 \t\t= ");
    BN_print_fp(stdout, bn1);
    printf("\n");


    BIGNUM *bn2 = BN_new();
    printf("bn2 \t\t= ");
    BN_set_word(bn2, 124);
    BN_print_fp(stdout, bn2);
    printf("\n");

    BIGNUM *res = BN_new();
    printf("bn1 + bn2 \t= ");
    BN_add(res, bn1, bn2);
    BN_print_fp(stdout, res);
    printf("\n");

    BN_CTX *ctx = BN_CTX_new();
    BN_mod(res, bn1, bn2, ctx);
    printf("bn1 mod bn2 = ");
    BN_print_fp(stdout, res);
    printf("\n");

    BN_free(bn1);
    BN_free(bn2);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}
