#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 4096

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv){
       
       
        unsigned char key[] = "keykeykeykeykeykey";

        if(argc != 3){
            fprintf(stderr,"Invalid parameters. Usage: %s file file2\n",argv[0]);
            exit(1);
        }


        FILE *f1;
        if((f1 = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }

        FILE *f2;
        if((f2 = fopen(argv[2],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }

        /* Load the human readable error strings for libcrypto */
        ERR_load_crypto_strings();
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

       //EVP_MD_CTX *EVP_MD_CTX_new(void);
       //pedantic mode? Check if md == NULL
		EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        // Returns 1 for success and 0 for failure.
        EVP_PKEY *hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));
        if(hkey == NULL)
            handle_errors();
 
        if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
            handle_errors();

        size_t n1;
        unsigned char buffer1[MAXBUF];
        while((n1 = fread(buffer1,1,MAXBUF,f1)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!EVP_DigestSignUpdate(hmac_ctx, buffer1, n1))
                handle_errors();
        }

        size_t n2;
        unsigned char buffer2[MAXBUF];
        while((n2 = fread(buffer2,1,MAXBUF,f2)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!EVP_DigestSignUpdate(hmac_ctx, buffer2, n2))
                handle_errors();
        }

        unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
        size_t hmac_len = EVP_MD_size(EVP_sha256());

        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned size_t *s);
        // EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len);
        if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
            handle_errors();

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(hmac_ctx);

        printf("CRYPTO23{");
        for(int i = 0; i < hmac_len; i++)
			     printf("%02x", hmac_value[i]);
        printf("}\n");

        fclose(f1);
        fclose(f2);


        // completely free all the cipher data
        CRYPTO_cleanup_all_ex_data();
        /* Remove error strings */
        ERR_free_strings();


	return 0;

}