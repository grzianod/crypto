#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void handle_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Generating public key pair */
    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne, RSA_F4)) //Fermat 4
        handle_error();

    RSA *rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_error();

    FILE *rsa_file;
    if((rsa_file = fopen("private.pem", "w")) == NULL) {
        fprintf(stderr,"Error opening \"private.pem\" file.\n\n");
        exit(1);
    }

    //fwrite(rsa_keypair, 1, sizeof(rsa_keypair), rsa_file);
    //PEM_write_RSAPrivateKey() can encrypt the private key on the file
    if(!PEM_write_RSAPrivateKey(rsa_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_error();

    fclose(rsa_file);


    if((rsa_file = fopen("public.pem", "w")) == NULL) {
        fprintf(stderr,"Error opening \"public.pem\" file.\n\n");
        exit(2);
    }

    if(!PEM_write_RSAPublicKey(rsa_file, rsa_keypair))
        handle_error();

    fclose(rsa_file);

    /*Using public key pair to perform asymmetrical encryption */
    unsigned char msg[] = "This is the message to encrypt\n";
    unsigned char encrypted_msg[RSA_size(rsa_keypair)];

    //the RSA_public_encrypt will use by default the public key to encrypt */
    int encrypted_len = RSA_public_encrypt(strlen(msg), msg, encrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
    if(encrypted_len < 0)
        handle_error();

    if((rsa_file=fopen("encrypted.enc", "w")) == NULL) {
        fprintf(stderr,"Error opening \"encrypted.enc\" file.\n\n");
            exit(3);
    }

    if(fwrite(encrypted_msg, 1, encrypted_len, rsa_file) < encrypted_len)
        handle_error();

    fclose(rsa_file);

    /* Decrypting the file */
    if((rsa_file=fopen("encrypted.enc", "r")) == NULL) {
        fprintf(stderr,"Error opening \"encrypted.enc\" file.\n\n");
        exit(4);
    }

    unsigned char decrypted_msg[RSA_size(rsa_keypair)];

    if((encrypted_len = fread(encrypted_msg, 1, RSA_size(rsa_keypair), rsa_file)) != RSA_size(rsa_keypair))
        handle_error();

    if(RSA_private_decrypt(encrypted_len, encrypted_msg, decrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING) < 0)
        handle_error();

    printf("Decrypted message: %s\n", decrypted_msg);

    RSA_free(rsa_keypair);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
