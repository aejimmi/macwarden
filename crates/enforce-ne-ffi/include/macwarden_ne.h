/*
 * macwarden_ne.h — C ABI for the macwarden NetworkExtension decision core.
 *
 * The Swift `NEFilterDataProvider` system extension links the `enforce-ne-ffi`
 * static library (`libenforce_ne_ffi.a`) and includes this header. The core
 * embeds the same `net::RuleSet` the daemon uses (loaded from ~/.macwarden/)
 * and decides each flow in-process, sub-millisecond, with no daemon round-trip.
 *
 * This header is hand-written (not cbindgen-generated): the ABI is four
 * functions plus an integer verdict, so a committed header is simpler,
 * deterministic, and avoids a build-time codegen dependency. Keep it in sync
 * with `src/ffi.rs` — the Rust side is the source of truth.
 *
 * Robustness contract (see src/lib.rs):
 *   - Thread-safe: `macwarden_ne_decide` may be called concurrently.
 *   - Fail-open: a null handle, bad input, or any internal panic yields ALLOW
 *     (decisions) or NULL/false (lifecycle). Enforcement never wedges the net.
 *   - No hot-path I/O: only init/reload touch the filesystem.
 */

#ifndef MACWARDEN_NE_H
#define MACWARDEN_NE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. Create with macwarden_ne_init*, release with macwarden_ne_free. */
typedef struct MacwardenNe MacwardenNe;

/* Verdict returned by macwarden_ne_decide. */
enum {
    MACWARDEN_NE_ALLOW = 0, /* allow the flow                       */
    MACWARDEN_NE_DENY  = 1, /* drop the flow                        */
    MACWARDEN_NE_LOG   = 2  /* allow but record (maps to allow)     */
};

/*
 * Initialize from the default base directory: $MACWARDEN_HOME if set, else
 * $HOME/.macwarden. Returns an owned handle, or NULL on failure.
 */
MacwardenNe *macwarden_ne_init(void);

/*
 * Initialize from an explicit base directory (chiefly for tests / non-default
 * installs). `dir` is a NUL-terminated UTF-8 path. Returns NULL on failure.
 */
MacwardenNe *macwarden_ne_init_at(const char *dir);

/*
 * Decide one flow. All string arguments are NUL-terminated UTF-8 or NULL;
 * NULL/empty are treated as unknown (Any).
 *
 *   code_id — signing code id (e.g. "com.apple.Safari"), or NULL
 *   path    — executable path, or NULL
 *   host    — destination hostname, or NULL
 *   ip      — destination IP (v4 or v6 text), or NULL
 *   port    — destination port; 0 means unknown
 *   proto   — IANA protocol number: 6 = TCP, 17 = UDP; other = unknown
 *
 * Returns one of MACWARDEN_NE_ALLOW / _DENY / _LOG. A null handle or any
 * internal error fails open to MACWARDEN_NE_ALLOW.
 */
int32_t macwarden_ne_decide(const MacwardenNe *handle,
                            const char *code_id,
                            const char *path,
                            const char *host,
                            const char *ip,
                            uint16_t port,
                            uint8_t proto);

/*
 * Rebuild the embedded rule set from disk and swap it in atomically. Safe to
 * call concurrently with macwarden_ne_decide. Returns true on success; on
 * failure the previous rule set is retained and this returns false.
 */
bool macwarden_ne_reload(const MacwardenNe *handle);

/* Release a handle from macwarden_ne_init*. NULL is a no-op. */
void macwarden_ne_free(MacwardenNe *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MACWARDEN_NE_H */
