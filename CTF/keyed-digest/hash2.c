#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int main() {
    const char *key_str = "this_is_my_secret";
    const unsigned char *data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\nUt enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.\nExcepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    const size_t data_len = strlen((const char*)data);
    unsigned char key[EVP_MAX_MD_SIZE];
    size_t key_len;
    const EVP_MD *md = EVP_sha256();
    unsigned char *hmac = NULL;
    size_t hmac_len;

    // Initialize the HMAC key
    key_len = strlen(key_str);
    memcpy(key, key_str, key_len);

    // Initialize the HMAC context
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_len, md, NULL);

    // Update the HMAC context with the data to be hashed
    HMAC_Update(ctx, data, data_len);

    // Finalize the HMAC and store the result in the hmac buffer
    hmac_len = EVP_MD_size(md);
    hmac = malloc(hmac_len);
    HMAC_Final(ctx, hmac, &hmac_len);

    // Print the HMAC result
    printf("HMAC: ");
    for (size_t i = 0; i < hmac_len; i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");

    // Clean up
    HMAC_CTX_free(ctx);
    free(hmac);

    return 0;
}
