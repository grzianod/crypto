#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
#define MAXBUF 1024

void handle_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {

    if(argc != 2) {
        fprintf(stderr, "Invalid arguments. Usage: %s input_file.\n", argv[0]);
        exit(1);
    }

    FILE *fp;
    if((fp = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the file \"%s\".\n", argv[1]);
        exit(2);
    }

    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "1234567890";


    HMAC_CTX *hmac = (HMAC_CTX *)HMAC_CTX_new();
    if(!HMAC_Init_ex(hmac, key, strlen(key), EVP_sha1(), NULL))     //NULL due to no external engines
        handle_error();

    int n=0; unsigned char buffer[MAXBUF];
    while((n = fread(buffer, 1, MAXBUF, fp)) > 0 ) {
        if(!HMAC_Update(hmac, buffer, n)) handle_error();
    }

    unsigned char hmac_value[HMAC_size(hmac)];
    int hmac_len =0;

    HMAC_Final(hmac, hmac_value, &hmac_len);

    printf("HMAC(%s) = ", argv[1]);
    for(int i=0; i<hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    ERR_free_strings();



    return 0;
}
