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

int main()
{
    const char *alg = OQS_SIG_alg_sphincs_shake_128s_simple;
    OQS_SIG *sig = OQS_SIG_new(alg);

    if (sig == NULL)
    {
        fprintf(stderr, "OQS_SIG_new() failed\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);

    if (public_key == NULL || secret_key == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS)
    {
        fprintf(stderr, "Keypair generation failed\n");
        return EXIT_FAILURE;
    }

    const char *msg = "Hello from SPHINCS+ client!";
    size_t msg_len = strlen(msg);

    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;

    DEFINE_TIMER_VARIABLES
    INITIALIZE_TIMER

    // Benchmark SPHINCS+ signature generation

    for (int i = 0; i < NUM_ITERATIONS; i++)
    {
        sig_len = 0;
        START_TIMER
        OQS_SIG_sign(sig, signature, &sig_len, (const uint8_t *)msg, msg_len, secret_key);
        STOP_TIMER
    }

    FINALIZE_TIMER
    PRINT_TIMER_HEADER
    PRINT_TIMER_AVG("SPHINCS+ Sign")
    PRINT_TIMER_FOOTER

    uint8_t buffer[MAXBUF];
    memcpy(buffer, &msg_len, 4);
    memcpy(buffer + 4, &sig_len, 4);
    memcpy(buffer + 8, msg, msg_len);
    memcpy(buffer + 8 + msg_len, signature, sig_len);
    memcpy(buffer + 8 + msg_len + sig_len, &sig->length_public_key, 4);
    memcpy(buffer + 8 + msg_len + sig_len + 4, public_key, sig->length_public_key);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
        return EXIT_FAILURE;
    }

    send(sock, buffer, 8 + msg_len + sig_len + 4 + sig->length_public_key, 0);
    printf("[CLIENT] Message and signature sent.\n");

    close(sock);
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}
