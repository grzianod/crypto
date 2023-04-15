#include <stdio.h>
#include <openssl/bn.h>


int main() {
    char num_string[] = "123456789012345678901234567890";
    char hex_string[] = "18EE90FF6C373E0EE4E3F0AD2";

    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    printf("dec2bn(%s) \t= ", num_string);
    BN_dec2bn(&bn1, num_string);
    BN_print_fp(stdout, bn1);
    printf("\n");

    printf("hex2bn(%s) \t\t= ", hex_string);
    BN_hex2bn(&bn2, hex_string);
    BN_print_fp(stdout, bn2);
    printf("\n");

    (!BN_cmp(bn1, bn2)) ? printf("bn1 = bn2\n") : printf("bn1 != bn2\n");

    printf("bn1 = %s\n", BN_bn2hex(bn1));
    printf("bn1 = %s\n", BN_bn2dec(bn1));



    BN_free(bn1);
    BN_free(bn2);

    return 0;
}
