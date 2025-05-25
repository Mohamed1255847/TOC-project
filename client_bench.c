#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ds_benchmark.h"

#define PORT 12345
#define MAXBUF 16384
#define NUM_ITERATIONS 100
#define KEY_REGEN_INTERVAL 10

int main() {
    const char *alg = OQS_SIG_alg_sphincs_shake_128s_simple;
    OQS_SIG *sig = OQS_SIG_new(alg);
    

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;

    const char *msg = "Hello from SPHINCS+ client!";
    size_t msg_len = strlen(msg);
    uint8_t *signature = malloc(sig->length_signature);

    // Benchmark loop
    DEFINE_TIMER_VARIABLES
    INITIALIZE_TIMER

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Generate new keypair every 10 iterations
        if (i % KEY_REGEN_INTERVAL == 0) {
            // Free old keys if they exist
            if (public_key) free(public_key);
            if (secret_key) free(secret_key);

            // Allocate new keys
            public_key = malloc(sig->length_public_key);
            secret_key = malloc(sig->length_secret_key);
            if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
                fprintf(stderr, "Keypair generation failed\n");
                return EXIT_FAILURE;
            }
        }

        // Sign the message
        size_t sig_len = 0;
        START_TIMER
        OQS_SIG_sign(sig, signature, &sig_len, (const uint8_t *)msg, msg_len, secret_key);
        STOP_TIMER

        // Prepare buffer with message, signature, and public key
        uint8_t buffer[MAXBUF];
        size_t pk_len = sig->length_public_key;

        memcpy(buffer, &msg_len, 4);
        memcpy(buffer + 4, &sig_len, 4);
        memcpy(buffer + 8, msg, msg_len);
        memcpy(buffer + 8 + msg_len, signature, sig_len);
        memcpy(buffer + 8 + msg_len + sig_len, &pk_len, 4);  // Send public key length
        memcpy(buffer + 8 + msg_len + sig_len + 4, public_key, pk_len);  // Send public key

        // Send to server (reconnect every time for simplicity)
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr = {0};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        send(sock, buffer, 8 + msg_len + sig_len + 4 + pk_len, 0);
        close(sock);
    }

    // Print timing results
    FINALIZE_TIMER
    PRINT_TIMER_HEADER
    PRINT_TIMER_AVG("SPHINCS+ Sign (with periodic keygen)")
    PRINT_TIMER_FOOTER

    // Cleanup
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);
    return 0;
}