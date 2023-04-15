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
    //BUT YOU SHOULD NOT USE KEYS AS CHARS!! ->
    EVP_PKEY *hmac_key = (EVP_PKEY *)EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));   //more secure key...


    //HMAC_CTX *hmac = (HMAC_CTX *)HMAC_CTX_new();
    EVP_MD_CTX *hmac = EVP_MD_CTX_new();

    //if(!HMAC_Init_ex(hmac, key, strlen(key), EVP_sha1(), NULL))     //NULL due to no external engines
    //handle_error();
    if(!EVP_DigestSignInit(hmac, NULL, EVP_sha1(), NULL, hmac_key))
        handle_error();

    int n=0; unsigned char buffer[MAXBUF];
    while((n = fread(buffer, 1, MAXBUF, fp)) > 0 ) {
        //if(!HMAC_Update(hmac, buffer, n)) handle_error();
        if(!EVP_DigestSignUpdate(hmac, buffer, n))
            handle_error();
    }

    //unsigned char hmac_value[HMAC_size(hmac)];
    unsigned char hmac_value[EVP_MD_size(EVP_sha1())];
    int hmac_len =0;

    //if(!HMAC_Final(hmac, hmac_value, &hmac_len))
    //handle_error();
    if(!EVP_DigestSignFinal(hmac, hmac_value, &hmac_len))
        handle_error();

    printf("HMAC(%s) = ", argv[1]);
    for(int i=0; i<hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    //VERIFICATION
    unsigned char hmac_in[] = "79ab79f215d7d2e4e7b95b5d49df849ab62eddff";
    unsigned char hmac_binary[strlen(hmac_in) / 2];

    for(int i=0; i< strlen(hmac_in)/2; i++) {
        sscanf(&(hmac_in[2*i]), "%2hhx", &(hmac_binary[i]));
    }

    //checking the length of the HMAC before the comparison. Once the length check is passed, compare HMACs
    if((hmac_len == strlen(hmac_in)/2) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0))
        printf("Verification successful!\n\n");
    else
        printf("Verification failure.\n\n");


    //once

    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
