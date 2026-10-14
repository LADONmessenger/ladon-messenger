//
//  Ladon-Bridging-Header.h
//  Ladon
//
//  Bridges Objective-C/C code to Swift
//

#ifndef Ladon_Bridging_Header_h
#define Ladon_Bridging_Header_h

// FIX H13: Anti-debug — PT_DENY_ATTACH prevents debugger attachment
// iOS SDK doesn't ship sys/ptrace.h, so we use the raw syscall number
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

static inline void ladon_deny_debugger(void) {
#if !DEBUG
    // SYS_ptrace = 26 on arm64 iOS.
    // syscall(2) ist auf iOS als deprecated markiert, funktioniert hier aber
    // weiterhin und ist der uebliche Weg fuer PT_DENY_ATTACH; ptrace() selbst
    // gehoert nicht zum oeffentlichen iOS-SDK. Die Warnung wird eng um diese
    // eine Zeile herum abgeschaltet, damit sie nicht 4x pro Build auftaucht —
    // an der Schutzfunktion selbst aendert das nichts.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
#pragma clang diagnostic pop
#endif
}

// FIX: C-convention wrappers for dyld functions (Swift @convention(thin) mismatch)
#include <mach-o/dyld.h>

static inline uint32_t ladon_dyld_image_count(void) {
    return _dyld_image_count();
}

static inline const char * _Nullable ladon_dyld_get_image_name(uint32_t image_index) {
    return _dyld_get_image_name(image_index);
}

static inline const struct mach_header * _Nullable ladon_dyld_get_image_header(uint32_t image_index) {
    return _dyld_get_image_header(image_index);
}

// liboqs Post-Quantum Crypto wrapper
#import "OQSWrapper.h"

// BLAKE3 cryptographic hash (FIPS-pending, used for HSig prehash + Token-ID + Bundle-ID)
#import "blake3/blake3.h"

// SQLCipher SQLite3 import (full-database encryption)
// SQLITE_HAS_CODEC must be defined BEFORE including sqlite3.h
// so that sqlite3_key() and sqlite3_rekey() are declared
#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC 1
#endif
#import "sqlite3.h"

// IPtProxy Bridge (Pluggable Transports)
#import "IPtProxyBridge.h"

// Tor Framework (Embedded Tor) - Direct function declarations
// Since tor.xcframework doesn't provide a module map, we declare the C API here
extern int tor_main(int argc, char **argv);

// Modern Tor API: tor_run_main + in-process control socket
// These symbols are exported by tor.xcframework (verified via nm).
// tor_run_main() accepts a configuration struct instead of raw argc/argv.
// tor_main_configuration_setup_control_socket() creates a pre-authenticated
// in-process control FD (socketpair) that survives iOS process suspension —
// unlike TCP listen sockets which iOS reclaims after 10+ min background.
typedef struct tor_main_configuration_t tor_main_configuration_t;
extern tor_main_configuration_t *tor_main_configuration_new(void);
extern void tor_main_configuration_free(tor_main_configuration_t *cfg);
extern int tor_main_configuration_set_command_line(tor_main_configuration_t *cfg, int argc, char **argv);
extern int tor_main_configuration_setup_control_socket(tor_main_configuration_t *cfg);
extern int tor_run_main(const tor_main_configuration_t *cfg);

#endif /* Ladon_Bridging_Header_h */
