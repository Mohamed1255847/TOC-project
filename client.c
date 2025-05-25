#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#define PORT 12345

int main() {
	OQS_init();
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128s_simple);
	if (sig == NULL) {
		fprintf(stderr, "Algorithm not enabled.\n");
		exit(EXIT_FAILURE);
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
	connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

	size_t msg_len, sig_len, pk_len;
	read(sock, &msg_len, sizeof(size_t));
	uint8_t *message = malloc(msg_len);
	read(sock, message, msg_len);

	read(sock, &sig_len, sizeof(size_t));
	uint8_t *signature = malloc(sig_len);
	read(sock, signature, sig_len);

	read(sock, &pk_len, sizeof(size_t));
	uint8_t *public_key = malloc(pk_len);
	read(sock, public_key, pk_len);

	OQS_STATUS rc = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
	if (rc == OQS_SUCCESS) {
		printf("Signature verified successfully.\n");
	} else {
		printf("Signature verification failed.\n");
	}

	close(sock);
	free(message);
	free(signature);
	free(public_key);
	OQS_SIG_free(sig);
	OQS_destroy();
	return 0;
}
