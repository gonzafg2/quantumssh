/*
 * The fixed-RNG test profile of scripts/capture-openssh-kex-vector.sh
 * (#216; RFC-0003 §"Test vectors and KAT plan", threat model §5.2.4).
 *
 * The capture preloads this into the quantumssh release binary for one
 * session. It is never linked into the binary and cargo never builds it,
 * so no build of quantumssh contains a fixed-RNG path. It replaces
 * glibc's getrandom(3), which the getrandom crate resolves with
 * dlsym(RTLD_DEFAULT) on linux-gnu, with a fixed-seed generator. It also
 * appends every draw to $FIXED_GETRANDOM_LOG as "<thread id> <length>
 * <hex>", so the capture can find the two draws the hybrid exchange
 * consumed.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t state = 216;

ssize_t getrandom(void *buf, size_t len, unsigned int flags)
{
	(void)flags;
	unsigned char *out = buf;

	pthread_mutex_lock(&lock);
	for (size_t i = 0; i < len; i++) {
		/* Knuth's MMIX LCG: only reproducibility matters here. */
		state = state * 6364136223846793005u + 1442695040888963407u;
		out[i] = (unsigned char)(state >> 56);
	}
	const char *path = getenv("FIXED_GETRANDOM_LOG");
	FILE *log = (path != NULL && len > 0) ? fopen(path, "a") : NULL;
	if (log != NULL) {
		fprintf(log, "%d %zu ", (int)gettid(), len);
		for (size_t i = 0; i < len; i++)
			fprintf(log, "%02x", out[i]);
		fputc('\n', log);
		fclose(log);
	}
	pthread_mutex_unlock(&lock);
	return (ssize_t)len;
}
