#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ds_benchmark.h"

#define PORT 12345
#define MAXBUF 16384
#define NUM_ITERATIONS 100

int main()
{
    // Use the same algorithm as your client
    const char *alg = OQS_SIG_alg_sphincs_shake_128s_simple;
    OQS_SIG *sig = OQS_SIG_new(alg);

    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new() failed\n");
        return EXIT_FAILURE;
    }

    // Allocate keys (not used for verification, but could be used for other purposes)
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        return EXIT_FAILURE;
    }

    printf("[SERVER] SPHINCS+ keypair generated.\n");

    // Set up server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    struct sockaddr_in address = {0};
    socklen_t addrlen = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }
    printf("[SERVER] Waiting for client...\n");

    int new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    if (new_socket < 0) {
        perror("accept");
        return EXIT_FAILURE;
    }

    uint8_t buffer[MAXBUF] = {0};
    ssize_t valread = read(new_socket, buffer, MAXBUF);
    if (valread < 0) {
        perror("read");
        return EXIT_FAILURE;
    }

    // Parse received buffer
    uint32_t msg_len, sig_len, pk_len;
    memcpy(&msg_len, buffer, 4);
    memcpy(&sig_len, buffer + 4, 4);
    memcpy(&pk_len, buffer + 8 + msg_len + sig_len, 4);
    uint8_t *msg = buffer + 8;
    uint8_t *sig_buf = buffer + 8 + msg_len;
    uint8_t *pk = buffer + 8 + msg_len + sig_len + 4;

    // One-time verification for correctness
    OQS_STATUS valid = OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len, pk);

    if (valid == OQS_SUCCESS) {
        printf("[SERVER] Signature is VALID!\n");
    } else {
        printf("[SERVER] Signature is INVALID!\n");
    }

    printf("[SERVER] Received message: %.*s\n", msg_len, msg);

    // Benchmark verification
    DEFINE_TIMER_VARIABLES
    INITIALIZE_TIMER

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        START_TIMER
        OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
        STOP_TIMER
    }

    FINALIZE_TIMER
    PRINT_TIMER_HEADER
    PRINT_TIMER_AVG("SPHINCS+ Verify")
    PRINT_TIMER_FOOTER

    // Cleanup
    close(new_socket);
    close(server_fd);
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);

    return 0;
}
