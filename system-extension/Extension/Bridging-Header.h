/*
 * Bridging header for the macwarden NEFilterDataProvider system extension.
 *
 * It pulls the hand-written C ABI of the Rust decision core into Swift so the
 * provider can call `macwarden_ne_init` / `macwarden_ne_decide` / `…_reload` /
 * `…_free` directly. The matching static library `libenforce_ne_ffi.a` is
 * linked by `build.sh`; the header lives in the Rust crate and is the single
 * source of truth for the ABI (see crates/enforce-ne-ffi/include/macwarden_ne.h).
 *
 * build.sh adds the crate's include directory to the Swift clang importer via
 *   -Xcc -I<repo>/crates/enforce-ne-ffi/include
 */
#import "macwarden_ne.h"
