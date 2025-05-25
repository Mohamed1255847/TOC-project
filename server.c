#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <oqs/oqs.h>

#define PORT 12345
#define MESSAGE_LEN 50

int main() {
	OQS_init();
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128s_simple);
	if (sig == NULL) {
		fprintf(stderr, "Algorithm not enabled.\n");
		exit(EXIT_FAILURE);
	}

	uint8_t *public_key = malloc(sig->length_public_key);
	uint8_t *secret_key = malloc(sig->length_secret_key);
	uint8_t message[MESSAGE_LEN];
	uint8_t *signature = malloc(sig->length_signature);
	size_t signature_len;

	OQS_randombytes(message, MESSAGE_LEN);
	OQS_SIG_keypair(sig, public_key, secret_key);
	OQS_SIG_sign(sig, signature, &signature_len, message, MESSAGE_LEN, secret_key);

	// Set up socket
	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	bind(server_fd, (struct sockaddr *)&address, sizeof(address));
	listen(server_fd, 1);

	int client_socket = accept(server_fd, NULL, NULL);

	// Send message, signature, public key (lengths first)
	size_t msg_len = MESSAGE_LEN;
	write(client_socket, &msg_len, sizeof(size_t));
	write(client_socket, message, MESSAGE_LEN);
	write(client_socket, &signature_len, sizeof(size_t));
	write(client_socket, signature, signature_len);
	write(client_socket, &sig->length_public_key, sizeof(size_t));
	write(client_socket, public_key, sig->length_public_key);

	printf("Message, signature, and public key sent to client.\n");

	// Clean up
	close(client_socket);
	close(server_fd);
	free(public_key);
	free(secret_key);
	free(signature);
	OQS_SIG_free(sig);
	OQS_destroy();
	return 0;
}
