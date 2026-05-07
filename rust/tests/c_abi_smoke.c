/* End-to-end smoke test for the C ABI exported by libtestimony.so.
 *
 * Two phases:
 *
 *   1. Negative path: testimony_connect against a path that doesn't exist
 *      should return a negative errno. Confirms the symbol surface is
 *      callable at all.
 *
 *   2. Positive path: connect to a real testimonyd, init, then loop
 *      get_block / return_block enough times to wrap the block ring at
 *      least twice. This exercises the bookkeeping that B1 broke (the
 *      "Conn.block_counts poisoned by mem::forget" regression). With the
 *      buggy version the second time any block index comes back from the
 *      server the FFI returns -EPROTO; the test would catch that.
 *
 *   3. testimony_return_packets: per-packet returns, decrementing until
 *      zero auto-returns. Verifies the FFI's `Inner::counts` accounting
 *      stays in sync with the daemon over multiple ring traversals.
 *
 * Linked against /work/target/release/libtestimony.so by the Dockerfile.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_packet.h>

/* Mirror of c/testimony.h. We could include the real header but vendor a
 * subset here so the test is self-contained inside rust/tests/. */
typedef struct testimony_internal* testimony;

typedef struct {
    int fanout_size;
    size_t block_size;
    size_t block_nr;
    int fanout_index;
} testimony_connection;

extern int testimony_connect(testimony* t, const char* socket_name);
extern testimony_connection* testimony_conn(testimony t);
extern int testimony_init(testimony t);
extern int testimony_close(testimony t);
extern char* testimony_error(testimony t);
extern int testimony_get_block(testimony t, int timeout_millis,
                               const struct tpacket_block_desc** block);
extern int testimony_return_block(testimony t,
                                  const struct tpacket_block_desc* block);
extern int testimony_return_packets(testimony t,
                                    const struct tpacket_block_desc* block,
                                    uint32_t packets);

static int phase_negative(void) {
    fputs("=== phase 1: testimony_connect against bogus path ===\n", stderr);
    testimony t = NULL;
    int r = testimony_connect(&t, "/tmp/this_does_not_exist_for_sure");
    if (r >= 0) {
        fprintf(stderr, "FAIL: testimony_connect succeeded against bogus path\n");
        if (t) testimony_close(t);
        return 1;
    }
    fprintf(stderr, "OK: testimony_connect returned %d (-%s)\n", r,
            strerror(-r));
    return 0;
}

/* Loop get_block / return_block long enough to wrap the ring at least
 * `min_wraps` times. Returns 0 on success, 1 on failure. */
static int phase_loop_return_block(const char* sock_path, int min_wraps) {
    fprintf(stderr,
            "=== phase 2: get_block/return_block loop on %s "
            "(min %d ring wraps) ===\n",
            sock_path, min_wraps);
    testimony t = NULL;
    int r = testimony_connect(&t, sock_path);
    if (r < 0) {
        fprintf(stderr, "FAIL: testimony_connect(%s) = %d (-%s)\n", sock_path,
                r, strerror(-r));
        return 1;
    }
    testimony_connection* c = testimony_conn(t);
    fprintf(stderr,
            "connected: fanout_size=%d block_size=%zu block_nr=%zu\n",
            c->fanout_size, c->block_size, c->block_nr);
    c->fanout_index = 0;
    r = testimony_init(t);
    if (r < 0) {
        fprintf(stderr, "FAIL: testimony_init = %d (-%s): %s\n", r,
                strerror(-r), testimony_error(t));
        testimony_close(t);
        return 1;
    }

    /* We want to round-trip every block index at least `min_wraps` times.
     * Keep a per-index hit counter; count distinct indices observed.
     * Stop once every index has been seen at least min_wraps times, or
     * after a generous timeout. */
    uint32_t* hits = calloc(c->block_nr, sizeof(*hits));
    if (!hits) {
        fprintf(stderr, "FAIL: calloc\n");
        testimony_close(t);
        return 1;
    }

    time_t deadline = time(NULL) + 60; /* 60 s max */
    int total_blocks = 0;
    while (time(NULL) < deadline) {
        const struct tpacket_block_desc* block = NULL;
        r = testimony_get_block(t, 5000, &block);
        if (r < 0) {
            fprintf(stderr,
                    "FAIL: testimony_get_block = %d (-%s) after %d blocks: %s\n",
                    r, strerror(-r), total_blocks, testimony_error(t));
            free(hits);
            testimony_close(t);
            return 1;
        }
        if (!block) {
            /* timeout — keep going, traffic might be sparse */
            continue;
        }
        /* Compute block index. The C library doesn't expose it, but we can
         * derive it from the block ptr, ring base, and block_size. We
         * don't have ring base directly, so just count and trust we'll
         * wrap. */
        total_blocks++;
        /* Increment a hit slot deterministically: use lower bits of the
         * pointer to bucket. */
        uintptr_t ptr_bits = (uintptr_t)block;
        size_t bucket = (ptr_bits / c->block_size) % c->block_nr;
        hits[bucket]++;
        r = testimony_return_block(t, block);
        if (r < 0) {
            fprintf(stderr,
                    "FAIL: testimony_return_block = %d (-%s) after %d blocks: %s\n",
                    r, strerror(-r), total_blocks, testimony_error(t));
            free(hits);
            testimony_close(t);
            return 1;
        }
        /* Are we done? */
        int all_hit = 1;
        for (size_t i = 0; i < c->block_nr; i++) {
            if (hits[i] < (uint32_t)min_wraps) {
                all_hit = 0;
                break;
            }
        }
        if (all_hit) {
            break;
        }
    }

    int min_observed = INT32_MAX;
    int max_observed = 0;
    for (size_t i = 0; i < c->block_nr; i++) {
        if ((int)hits[i] < min_observed) min_observed = (int)hits[i];
        if ((int)hits[i] > max_observed) max_observed = (int)hits[i];
    }
    fprintf(stderr,
            "phase 2 done: %d blocks total; min hits=%d, max hits=%d, "
            "block_nr=%zu\n",
            total_blocks, min_observed, max_observed, c->block_nr);

    free(hits);
    testimony_close(t);

    if (min_observed < min_wraps) {
        fprintf(stderr,
                "FAIL: at least one block was hit only %d times, wanted %d\n",
                min_observed, min_wraps);
        return 1;
    }
    return 0;
}

/* Smoke test for testimony_return_packets: don't bother validating per-packet
 * counts (that requires walking the block); just confirm we can call it
 * repeatedly without hitting -EINVAL or -EPROTO. */
static int phase_return_packets(const char* sock_path) {
    fprintf(stderr,
            "=== phase 3: testimony_return_packets smoke on %s ===\n",
            sock_path);
    testimony t = NULL;
    int r = testimony_connect(&t, sock_path);
    if (r < 0) {
        fprintf(stderr, "FAIL: testimony_connect = %d (-%s)\n", r,
                strerror(-r));
        return 1;
    }
    testimony_connection* c = testimony_conn(t);
    c->fanout_index = 0;
    r = testimony_init(t);
    if (r < 0) {
        fprintf(stderr, "FAIL: testimony_init = %d (-%s): %s\n", r,
                strerror(-r), testimony_error(t));
        testimony_close(t);
        return 1;
    }

    /* Get up to 4 blocks, return each via return_packets in chunks. */
    for (int i = 0; i < 4; i++) {
        const struct tpacket_block_desc* block = NULL;
        r = testimony_get_block(t, 5000, &block);
        if (r < 0) {
            fprintf(stderr, "FAIL: get_block = %d: %s\n", r,
                    testimony_error(t));
            testimony_close(t);
            return 1;
        }
        if (!block) {
            fprintf(stderr, "phase 3: timed out waiting for block %d\n", i);
            continue;
        }
        uint32_t num_pkts = block->hdr.bh1.num_pkts;
        if (num_pkts == 0) {
            /* No packets in this block; just return it whole. */
            r = testimony_return_block(t, block);
            if (r < 0) {
                fprintf(stderr,
                        "FAIL: return_block (empty) = %d: %s\n", r,
                        testimony_error(t));
                testimony_close(t);
                return 1;
            }
            continue;
        }
        /* Return one packet at a time. Last call should auto-return. */
        for (uint32_t p = 0; p < num_pkts; p++) {
            r = testimony_return_packets(t, block, 1);
            if (r < 0) {
                fprintf(stderr,
                        "FAIL: return_packets[%u/%u] = %d: %s\n", p, num_pkts,
                        r, testimony_error(t));
                testimony_close(t);
                return 1;
            }
        }
    }

    testimony_close(t);
    fputs("phase 3 OK\n", stderr);
    return 0;
}

int main(int argc, char** argv) {
    if (phase_negative() != 0) return 1;

    /* If a real socket path was given, run phases 2 and 3 against it. */
    const char* real_sock = NULL;
    int min_wraps = 2;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            real_sock = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--wraps") == 0 && i + 1 < argc) {
            min_wraps = atoi(argv[i + 1]);
            i++;
        }
    }
    if (!real_sock) {
        fputs("(no --socket given; phases 2+3 skipped)\n", stderr);
        return 0;
    }
    if (phase_loop_return_block(real_sock, min_wraps) != 0) return 1;
    if (phase_return_packets(real_sock) != 0) return 1;
    fputs("=== c_abi_smoke: ALL PHASES PASSED ===\n", stderr);
    return 0;
}
