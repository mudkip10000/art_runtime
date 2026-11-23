/*
 * scanner_hooks native interception layer.
 *
 * The managed rules in scanner_hooks_rules.inc only intercept framework (Java) calls. Hardened apps
 * (V-OS, Ant/Alipay, DexProtector) read the same anti-debug / anti-emulator signals in NATIVE code,
 * straight through libc, bypassing the managed facades entirely. This layer intercepts those native
 * reads in the target process only, so the app sees clean values while the rest of the system (adbd,
 * the scanner's debugger) keeps seeing the real device.
 *
 * Two surfaces:
 *   - property reads: __system_property_get / _read / _read_callback -> spoofed values
 *   - file reads: read-only openat / open / fopen of sensitive /proc paths -> a sanitized copy
 *     (served from an in-memory fd); open / openat / fopen / access of root/hook paths -> ENOENT
 *
 * Only app-owned libraries (loaded from /data) are patched; system/vendor/apex modules are left
 * alone so the runtime and the graphics/HAL stacks keep reading the real device.
 *
 * Mechanism: PLT/GOT hooking (patch each loaded module's import table - data, not code, so it does
 * not trip code-integrity checks and leaves no inline trampolines). Libraries loaded after install
 * (the protector's own .so) are caught by a bounded re-patch thread (NativeRepatchThread). dlopen is
 * deliberately NOT hooked: it resolves libraries relative to the caller's linker namespace, so a
 * libart wrapper would break namespace-scoped loads (see the note near the hook table).
 *
 * FAIL-SAFE INVARIANT (as everywhere in scanner_hooks): any parse / patch / redirect failure must
 * degrade to "call the real libc function", never crash. Unrecognised inputs fall through to the
 * saved original; a symbol whose original did not resolve is left unpatched.
 *
 * Textually included by scanner_hooks.cc from inside its anonymous namespace, after the managed
 * engine. Not a standalone translation unit; all headers it needs are included at the top of
 * scanner_hooks.cc.
 */

// ---------------------------------------------------------------------------
// Spoofed property values (mirror the managed SystemProperties rules)
// ---------------------------------------------------------------------------
struct NativePropSpoof {
  const char* name;
  const char* value;
};
const NativePropSpoof kNativePropSpoofs[] = {
    {"sys.usb.state", "mtp"},
    {"sys.usb.config", "mtp"},
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.flash.locked", "1"},
    {"ro.kernel.qemu", "0"},
    {"ro.boot.qemu", "0"},
    {"service.adb.tcp.port", ""},
    {"ro.hardware", "exynos2100"},
    {"ro.product.brand", "google"},
    {"ro.product.manufacturer", "google"},
    {"ro.product.device", "pixel"},
    {"ro.product.model", "pixel"},
};

// Returns the spoofed value for `name`, or nullptr to pass through. Exact match only (the probes use
// exact keys); qemu.* / init.svc.qemu* are handled by the "contains qemu" fallback below.
const char* NativePropSpoofFor(const char* name) {
  if (name == nullptr) {
    return nullptr;
  }
  for (const NativePropSpoof& s : kNativePropSpoofs) {
    if (std::strcmp(s.name, name) == 0) {
      return s.value;
    }
  }
  // Emulator giveaway namespaces: report absent (empty) so a "<prop> is set -> emulator" check fails.
  if (std::strstr(name, "qemu") != nullptr || std::strstr(name, "goldfish") != nullptr) {
    return "";
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Sensitive file paths and their sanitizers
// ---------------------------------------------------------------------------
// Debug/instrumentation TCP ports whose rows are stripped from /proc/net/tcp*: adb (5555), adb
// server (5037), and the frida-server default range (27042-27047). Stored as the hex the kernel
// prints in the local/remote address field (":PORT" upper-case hex).
const char* const kDebugPortHex[] = {":15B3", ":13AD", ":69A2", ":69A3", ":69A4", ":69A5",
                                     ":69A6", ":69A7"};

// Regular files served from a sanitized in-memory copy (prefix match); the sanitizer is chosen by
// path. Directories (e.g. /proc/self/task) are excluded - they are read via opendir/readdir, not as
// files.
const char* const kRedirectPaths[] = {
    "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6",
    "/proc/cpuinfo", "/proc/self/maps", "/proc/mounts",
    "/proc/self/mountinfo", "/proc/ioports",
};

// Paths an access()/open() of which is forced to fail (ENOENT): common root / hook artifacts a
// hardened app probes. Emulator device nodes (/dev/goldfish_pipe, /dev/qemu_pipe, ...) are
// deliberately NOT denied - the GPU/sensor emulation in the app process opens them, so denying would
// break rendering; emulator detection is covered instead via the property spoof and /proc scrubbing.
const char* const kDenyPaths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su", "/system/app/Superuser.apk",
    "/sbin/magisk", "/system/bin/magisk", "/data/adb/magisk", "/cache/magisk",
    "/system/lib/libriruloader.so", "/system/framework/XposedBridge.jar",
};

// Substrings whose lines are dropped from /proc/self/maps and /proc/mounts (hook / root / emulator
// infrastructure that an app scans these files for).
const char* const kMapsDropSubstrings[] = {
    "frida", "gum-js", "libgum", "xposed", "XposedBridge", "riru", "zygisk", "magisk",
    "/memfd:", "goldfish", "ranchu", "qemu",
};

bool PathInList(const char* path, const char* const* list, size_t n) {
  if (path == nullptr) {
    return false;
  }
  for (size_t i = 0; i < n; ++i) {
    if (std::strcmp(path, list[i]) == 0) {
      return true;
    }
  }
  return false;
}

bool PathPrefixInList(const char* path, const char* const* list, size_t n) {
  if (path == nullptr) {
    return false;
  }
  for (size_t i = 0; i < n; ++i) {
    size_t len = std::strlen(list[i]);
    if (std::strncmp(path, list[i], len) == 0) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Saved originals (real libc implementations, resolved via dlsym in ResolveNativeOriginals)
// ---------------------------------------------------------------------------
using PropGetFn = int (*)(const char*, char*);
using PropReadFn = int (*)(const void*, char*, char*);
using PropReadCbFn = void (*)(const void*, void (*)(void*, const char*, const char*, uint32_t), void*);
using OpenFn = int (*)(const char*, int, ...);
using OpenatFn = int (*)(int, const char*, int, ...);
using FopenFn = FILE* (*)(const char*, const char*);
using AccessFn = int (*)(const char*, int);

// Resolved libc implementations, set once by ResolveNativeOriginals via dlsym - NOT captured from a
// module's GOT slot, which may still hold that module's lazy-binding PLT stub (calling that stub
// after we patch the slot would re-enter our own hook -> infinite recursion). Atomic with
// release/acquire so an app thread that observes a live hook also observes the stored original (the
// install runs outside any suspend-all barrier).
std::atomic<PropGetFn> g_real_prop_get{nullptr};
std::atomic<PropReadFn> g_real_prop_read{nullptr};
std::atomic<PropReadCbFn> g_real_prop_read_cb{nullptr};
std::atomic<OpenFn> g_real_open{nullptr};
std::atomic<OpenatFn> g_real_openat{nullptr};
std::atomic<FopenFn> g_real_fopen{nullptr};
std::atomic<AccessFn> g_real_access{nullptr};

std::atomic<bool> g_native_hooks_installed{false};
std::mutex g_native_patch_lock;

// Set true while our own replacement runs, so a sanitizer that reads the real file through the saved
// original openat is not itself redirected (defence-in-depth; we use the saved original directly).
thread_local bool t_in_native_hook = false;

// RAII guard for the re-entrancy flag: clears it on scope exit even if the guarded call unwinds, so a
// throwing path (e.g. bad_alloc in the sanitizer, or an app property callback) cannot leave hooks
// disabled on this thread. Only enter the guard once the flag is known to be clear.
struct NativeHookReentryGuard {
  NativeHookReentryGuard() { t_in_native_hook = true; }
  ~NativeHookReentryGuard() { t_in_native_hook = false; }
};

// ---------------------------------------------------------------------------
// Sanitized-content generation (served from a memfd)
// ---------------------------------------------------------------------------

// Reads an entire file through the saved original openat into `out`. Returns false on any error.
bool ReadWholeFileRaw(const char* path, std::string* out) {
  OpenatFn real_openat = g_real_openat.load(std::memory_order_acquire);
  if (real_openat == nullptr) {
    return false;
  }
  int fd = real_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  out->clear();
  // Heap buffer (not a stack array): ART caps per-function stack frame size, and when this and its
  // callers inline on the open() hook path a 4 KB on-stack buffer blows that limit (ld.lld error).
  std::vector<char> buf(4096);
  for (;;) {
    ssize_t n = read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return false;
    }
    if (n == 0) {
      break;
    }
    out->append(buf.data(), static_cast<size_t>(n));
  }
  close(fd);
  return true;
}

// True if the /proc/net line references one of the debug/instrumentation ports.
bool LineHasDebugPort(const std::string& line) {
  for (const char* p : kDebugPortHex) {
    if (line.find(p) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// True if the line contains any of the drop substrings (maps / mounts sanitizer).
bool LineHasDropSubstring(const std::string& line) {
  for (const char* s : kMapsDropSubstrings) {
    if (line.find(s) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// Sanitizes already-read file content for `path` into `out`. Split from the file read so both the libc
// redirect (BuildSanitizedContent) and the syscall-level spoofer can reuse it. Always returns true;
// an unrecognised path passes the content through unchanged.
bool SanitizeContent(const char* path, const std::string& real, std::string* out) {
  const bool is_net = (std::strncmp(path, "/proc/net/", 10) == 0);
  // smaps shares maps' format, so the same emulator/hook line filter applies.
  const bool is_maps_like =
      (std::strcmp(path, "/proc/self/maps") == 0 || std::strcmp(path, "/proc/self/smaps") == 0 ||
       std::strcmp(path, "/proc/mounts") == 0 || std::strcmp(path, "/proc/self/mountinfo") == 0);
  out->clear();
  if (is_net || is_maps_like) {
    // Line-filter: drop rows that reveal a debug socket (net) or hook/root/emulator infra (maps).
    size_t start = 0;
    bool first = true;
    while (start <= real.size()) {
      size_t nl = real.find('\n', start);
      std::string line = real.substr(start, (nl == std::string::npos) ? std::string::npos : nl - start);
      bool drop = false;
      if (is_net && !first && LineHasDebugPort(line)) {
        drop = true;  // keep the header row (first), drop debug-port rows
      }
      if (is_maps_like && LineHasDropSubstring(line)) {
        drop = true;
      }
      if (!drop) {
        out->append(line);
        if (nl != std::string::npos) {
          out->push_back('\n');
        }
      }
      first = false;
      if (nl == std::string::npos) {
        break;
      }
      start = nl + 1;
    }
    return true;
  }
  if (std::strcmp(path, "/proc/self/status") == 0) {
    // Zero TracerPid so a ptrace/debugger check reads "not traced".
    *out = real;
    size_t pos = out->find("TracerPid:");
    if (pos != std::string::npos) {
      size_t eol = out->find('\n', pos);
      out->replace(pos, (eol == std::string::npos ? out->size() : eol) - pos, "TracerPid:\t0");
    }
    return true;
  }
  if (std::strcmp(path, "/proc/cpuinfo") == 0 || std::strcmp(path, "/proc/ioports") == 0) {
    // Scrub emulator-identifying tokens with a same-length replacement, so offsets stay unchanged.
    *out = real;
    static const char* const kTokens[] = {"goldfish", "ranchu", "Goldfish", "Ranchu", "qemu", "QEMU"};
    for (const char* tok : kTokens) {
      size_t pos = 0;
      const size_t tlen = std::strlen(tok);
      while ((pos = out->find(tok, pos)) != std::string::npos) {
        out->replace(pos, tlen, std::string(tlen, 'x'));
        pos += tlen;
      }
    }
    return true;
  }
  *out = real;  // unrecognised: pass through unchanged
  return true;
}

// Produces the sanitized content for `path`. Returns false to fall through to the real file.
bool BuildSanitizedContent(const char* path, std::string* out) {
  std::string real;
  if (!ReadWholeFileRaw(path, &real)) {
    return false;
  }
  return SanitizeContent(path, real, out);
}

// Creates an in-memory fd holding `content`, positioned at 0. Returns -1 on failure.
int MakeMemContentFd(const std::string& content) {
  int fd = static_cast<int>(syscall(__NR_memfd_create, "s", 1u /* MFD_CLOEXEC: don't leak across exec */));
  if (fd < 0) {
    return -1;
  }
  size_t off = 0;
  while (off < content.size()) {
    ssize_t n = write(fd, content.data() + off, content.size() - off);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    off += static_cast<size_t>(n);
  }
  lseek(fd, 0, SEEK_SET);
  return fd;
}

// If `path` should be redirected, returns an fd to sanitized content; else -1 (caller uses the real
// function). On any sanitizer failure returns -1 (fall through).
int RedirectOpenIfSensitive(const char* path) {
  if (!PathPrefixInList(path, kRedirectPaths, sizeof(kRedirectPaths) / sizeof(kRedirectPaths[0]))) {
    return -1;
  }
  std::string content;
  if (!BuildSanitizedContent(path, &content)) {
    return -1;
  }
  return MakeMemContentFd(content);
}

// ---------------------------------------------------------------------------
// Replacement functions
// ---------------------------------------------------------------------------

int My__system_property_get(const char* name, char* value) {
  const char* spoof = NativePropSpoofFor(name);
  if (g_verbose && name != nullptr) {
    LOG(INFO) << "scanner-native: __system_property_get '" << name << "'"
              << (spoof != nullptr ? " (spoofed)" : "");
  }
  if (spoof != nullptr && value != nullptr) {
    size_t len = std::strlen(spoof);
    if (len > 91u) {
      len = 91u;  // PROP_VALUE_MAX - 1
    }
    std::memcpy(value, spoof, len);
    value[len] = '\0';
    return static_cast<int>(len);
  }
  PropGetFn real = g_real_prop_get.load(std::memory_order_acquire);
  if (real != nullptr) {
    return real(name, value);
  }
  if (value != nullptr) {
    value[0] = '\0';
  }
  return 0;
}

// __system_property_read(pi, name, value): read real, then spoof the value if the name matches.
int My__system_property_read(const void* pi, char* name, char* value) {
  PropReadFn real = g_real_prop_read.load(std::memory_order_acquire);
  if (real == nullptr) {
    return -1;
  }
  int r = real(pi, name, value);
  if (r >= 0 && name != nullptr && value != nullptr) {
    const char* spoof = NativePropSpoofFor(name);
    if (g_verbose) {
      LOG(INFO) << "scanner-native: __system_property_read '" << name << "'"
                << (spoof != nullptr ? " (spoofed)" : "");
    }
    if (spoof != nullptr) {
      size_t len = std::strlen(spoof);
      if (len > 91u) {
        len = 91u;
      }
      std::memcpy(value, spoof, len);
      value[len] = '\0';
      return static_cast<int>(len);
    }
  }
  return r;
}

// Trampoline state for __system_property_read_callback: substitute the value before the app's cb.
// The app's real callback is passed through as the cookie (bridged via uintptr_t to avoid an
// object/function pointer cast); its real cookie is stashed thread-local for the synchronous call.
thread_local void* t_app_prop_cookie = nullptr;

void NativePropCbTrampoline(void* cookie, const char* name, const char* value, uint32_t serial) {
  const char* spoof = NativePropSpoofFor(name);
  if (g_verbose && name != nullptr) {
    LOG(INFO) << "scanner-native: __system_property_read_callback '" << name << "'"
              << (spoof != nullptr ? " (spoofed)" : "");
  }
  auto app_cb = reinterpret_cast<void (*)(void*, const char*, const char*, uint32_t)>(
      reinterpret_cast<uintptr_t>(cookie));
  app_cb(t_app_prop_cookie, name, (spoof != nullptr) ? spoof : value, serial);
}

void My__system_property_read_callback(const void* pi,
                                       void (*callback)(void*, const char*, const char*, uint32_t),
                                       void* cookie) {
  PropReadCbFn real = g_real_prop_read_cb.load(std::memory_order_acquire);
  if (real == nullptr || callback == nullptr) {
    if (real != nullptr) {
      real(pi, callback, cookie);
    }
    return;
  }
  // Re-entrancy guard: nested reads use the real path (our trampoline uses thread_locals).
  if (t_in_native_hook) {
    real(pi, callback, cookie);
    return;
  }
  NativeHookReentryGuard guard;
  t_app_prop_cookie = cookie;
  real(pi, &NativePropCbTrampoline,
       reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(callback)));
}

// A redirect serves a read-only memfd snapshot, so it is only correct for a plain read-only open.
// O_TMPFILE is (__O_TMPFILE | O_DIRECTORY), so the O_DIRECTORY test also excludes it here.
bool OpenIsPlainRead(int flags) {
  return (flags & O_ACCMODE) == O_RDONLY && (flags & (O_CREAT | O_DIRECTORY | O_PATH)) == 0;
}

// The kernel consumes the mode argument for O_CREAT and for O_TMPFILE (which does not include the
// O_CREAT bit), so both must pull it from the varargs.
bool OpenNeedsMode(int flags) {
  return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE;
}

int My_openat(int dirfd, const char* path, int flags, ...) {
  mode_t mode = 0;
  if (OpenNeedsMode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = static_cast<mode_t>(va_arg(ap, int));
    va_end(ap);
  }
  if (!t_in_native_hook && dirfd == AT_FDCWD) {
    if (PathInList(path, kDenyPaths, sizeof(kDenyPaths) / sizeof(kDenyPaths[0]))) {
      errno = ENOENT;
      return -1;
    }
    if (OpenIsPlainRead(flags)) {
      int red;
      {
        NativeHookReentryGuard guard;
        red = RedirectOpenIfSensitive(path);
      }
      if (red >= 0) {
        return red;
      }
    }
  }
  OpenatFn real = g_real_openat.load(std::memory_order_acquire);
  if (real != nullptr) {
    return real(dirfd, path, flags, mode);
  }
  errno = ENOSYS;
  return -1;
}

int My_open(const char* path, int flags, ...) {
  mode_t mode = 0;
  if (OpenNeedsMode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = static_cast<mode_t>(va_arg(ap, int));
    va_end(ap);
  }
  if (!t_in_native_hook) {
    if (PathInList(path, kDenyPaths, sizeof(kDenyPaths) / sizeof(kDenyPaths[0]))) {
      errno = ENOENT;
      return -1;
    }
    if (OpenIsPlainRead(flags)) {
      int red;
      {
        NativeHookReentryGuard guard;
        red = RedirectOpenIfSensitive(path);
      }
      if (red >= 0) {
        return red;
      }
    }
  }
  OpenFn real = g_real_open.load(std::memory_order_acquire);
  if (real != nullptr) {
    return real(path, flags, mode);
  }
  errno = ENOSYS;
  return -1;
}

FILE* My_fopen(const char* path, const char* mode) {
  // Redirect only a read-only fopen ("r", no "+"): the memfd snapshot is read-only.
  bool plain_read = mode != nullptr && mode[0] == 'r' && std::strchr(mode, '+') == nullptr;
  if (!t_in_native_hook) {
    if (PathInList(path, kDenyPaths, sizeof(kDenyPaths) / sizeof(kDenyPaths[0]))) {
      errno = ENOENT;
      return nullptr;
    }
    if (plain_read) {
      int red;
      {
        NativeHookReentryGuard guard;
        red = RedirectOpenIfSensitive(path);
      }
      if (red >= 0) {
        FILE* f = fdopen(red, "r");
        if (f != nullptr) {
          return f;
        }
        close(red);  // fall through on fdopen failure
      }
    }
  }
  FopenFn real = g_real_fopen.load(std::memory_order_acquire);
  if (real != nullptr) {
    return real(path, mode);
  }
  errno = ENOSYS;
  return nullptr;
}

int My_access(const char* path, int amode) {
  if (!t_in_native_hook &&
      PathInList(path, kDenyPaths, sizeof(kDenyPaths) / sizeof(kDenyPaths[0]))) {
    errno = ENOENT;
    return -1;
  }
  AccessFn real = g_real_access.load(std::memory_order_acquire);
  if (real != nullptr) {
    return real(path, amode);
  }
  errno = ENOSYS;
  return -1;
}

// dlopen / android_dlopen_ext are deliberately NOT hooked: they resolve libraries relative to the
// CALLER's linker namespace (derived from the return address), so wrapping them in libart would make
// the linker use libart's namespace and break namespace-scoped loads (e.g. libhwui loading
// libandroid for ASurfaceControl). Libraries loaded after install (the protector's own .so) are
// instead caught by the short-lived re-patch thread started from InstallNativeHooks.

// ---------------------------------------------------------------------------
// The hook table: symbol -> replacement (originals are resolved by name in ResolveNativeOriginals)
// ---------------------------------------------------------------------------
struct NativeHookEntry {
  const char* symbol;
  void* replacement;
};
const NativeHookEntry kNativeHooks[] = {
    {"__system_property_get", reinterpret_cast<void*>(&My__system_property_get)},
    {"__system_property_read", reinterpret_cast<void*>(&My__system_property_read)},
    {"__system_property_read_callback", reinterpret_cast<void*>(&My__system_property_read_callback)},
    {"openat", reinterpret_cast<void*>(&My_openat)},
    {"open", reinterpret_cast<void*>(&My_open)},
    {"fopen", reinterpret_cast<void*>(&My_fopen)},
    {"access", reinterpret_cast<void*>(&My_access)},
};

const NativeHookEntry* NativeHookForSymbol(const char* name) {
  for (const NativeHookEntry& e : kNativeHooks) {
    if (std::strcmp(e.symbol, name) == 0) {
      return &e;
    }
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// GOT patching
// ---------------------------------------------------------------------------
#if defined(__aarch64__)
#define SCANNER_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define SCANNER_R_GLOB_DAT R_AARCH64_GLOB_DAT
#elif defined(__x86_64__)
#define SCANNER_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define SCANNER_R_GLOB_DAT R_X86_64_GLOB_DAT
#else
// Only arm64 / x86_64 are implemented. Impossible values keep the code compiling and inert on the
// other arches the apex is also built for (32-bit arm/x86), where this layer is simply never active.
#define SCANNER_R_JUMP_SLOT 0xffffffffu
#define SCANNER_R_GLOB_DAT 0xfffffffeu
#endif
// Relocation info accessors. Both supported arches are LP64; the 32-bit forms keep it compiling.
#if defined(__LP64__)
#define SCANNER_R_TYPE(i) ELF64_R_TYPE(i)
#define SCANNER_R_SYM(i) ELF64_R_SYM(i)
#else
#define SCANNER_R_TYPE(i) ELF32_R_TYPE(i)
#define SCANNER_R_SYM(i) ELF32_R_SYM(i)
#endif

// A .dynamic pointer value (STRTAB/SYMTAB/JMPREL/RELA) is stored either already-relocated (absolute)
// or as a load-relative offset; resolve against the module base.
uintptr_t ResolveDynPtr(ElfW(Addr) base, ElfW(Addr) val) {
  return (val < base) ? (base + val) : val;
}

// Patches one GOT slot to `replacement`. `in_relro` says whether the slot lies in the module's
// PT_GNU_RELRO range (made read-only by the linker) or in a still-writable segment such as a
// lazily-bound .got.plt. We widen the page to RW, store, then restore the protection the slot had
// before: PROT_READ for a RELRO slot, PROT_READ|PROT_WRITE otherwise. Forcing every slot to
// PROT_READ would fault later lazy-bind writes or neighbouring .data writes on a non-RELRO page. The
// store is release so a thread that loads the new pointer also sees everything it points at.
bool PatchGotSlot(void** slot, void* replacement, bool in_relro) {
  if (*slot == replacement) {
    return false;  // already ours
  }
  uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~(static_cast<uintptr_t>(sysconf(_SC_PAGESIZE)) - 1);
  size_t pagesz = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  if (mprotect(reinterpret_cast<void*>(page), pagesz, PROT_READ | PROT_WRITE) != 0) {
    return false;
  }
  __atomic_store_n(slot, replacement, __ATOMIC_RELEASE);
  mprotect(reinterpret_cast<void*>(page), pagesz, in_relro ? PROT_READ : (PROT_READ | PROT_WRITE));
  __builtin___clear_cache(reinterpret_cast<char*>(slot), reinterpret_cast<char*>(slot) + sizeof(void*));
  return true;
}

// Fail-safe gate: only patch a symbol once we actually hold the real libc function to pass through
// to. If a dlsym failed and we patched anyway, every call to that symbol in the patched module would
// hit our hook and get the no-resolve failure (ENOSYS / -1 / empty) instead of the real result.
bool NativeOriginalResolved(const char* symbol) {
  if (std::strcmp(symbol, "__system_property_get") == 0) {
    return g_real_prop_get.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "__system_property_read") == 0) {
    return g_real_prop_read.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "__system_property_read_callback") == 0) {
    return g_real_prop_read_cb.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "open") == 0) {
    return g_real_open.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "openat") == 0) {
    return g_real_openat.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "fopen") == 0) {
    return g_real_fopen.load(std::memory_order_acquire) != nullptr;
  }
  if (std::strcmp(symbol, "access") == 0) {
    return g_real_access.load(std::memory_order_acquire) != nullptr;
  }
  return false;
}

// Patches all of our hooked symbols in one module's relocation tables. [relro_start, relro_end) is
// the module's PT_GNU_RELRO range (empty if none), used to restore each slot's page protection.
void PatchModuleRelocs(ElfW(Addr) base, const ElfW(Rela)* rela, size_t count, const ElfW(Sym)* symtab,
                       const char* strtab, uintptr_t relro_start, uintptr_t relro_end) {
  if (rela == nullptr || symtab == nullptr || strtab == nullptr) {
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    const ElfW(Rela)& r = rela[i];
    uint32_t type = static_cast<uint32_t>(SCANNER_R_TYPE(r.r_info));
    if (type != SCANNER_R_JUMP_SLOT && type != SCANNER_R_GLOB_DAT) {
      continue;
    }
    uint32_t sym = static_cast<uint32_t>(SCANNER_R_SYM(r.r_info));
    const char* name = strtab + symtab[sym].st_name;
    const NativeHookEntry* e = NativeHookForSymbol(name);
    if (e == nullptr || !NativeOriginalResolved(e->symbol)) {
      continue;
    }
    uintptr_t slot_addr = base + r.r_offset;
    bool in_relro = (slot_addr >= relro_start && slot_addr < relro_end);
    PatchGotSlot(reinterpret_cast<void**>(slot_addr), e->replacement, in_relro);
  }
}

int NativePatchModuleCb(struct dl_phdr_info* info, size_t /*size*/, void* /*data*/) {
  const char* mname = (info->dlpi_name != nullptr) ? info->dlpi_name : "";
  // Only patch app-owned libraries, which are loaded from /data (the RASP's own .so is app-bundled
  // there). System, vendor, apex and product modules (libart, libc, the graphics and HAL stacks)
  // read these props legitimately, and spoofing their reads or redirecting their files can
  // destabilise the runtime or break rendering - e.g. the vendor GL/gralloc libs read ro.kernel.qemu.
  if (std::strstr(mname, "/data/") == nullptr) {
    return 0;
  }
  const ElfW(Dyn)* dyn = nullptr;
  uintptr_t relro_start = 0;
  uintptr_t relro_end = 0;
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr)& ph = info->dlpi_phdr[i];
    if (ph.p_type == PT_DYNAMIC) {
      dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + ph.p_vaddr);
    } else if (ph.p_type == PT_GNU_RELRO) {
      relro_start = info->dlpi_addr + ph.p_vaddr;
      relro_end = relro_start + ph.p_memsz;
    }
  }
  if (dyn == nullptr) {
    return 0;
  }
  const char* strtab = nullptr;
  const ElfW(Sym)* symtab = nullptr;
  const ElfW(Rela)* jmprel = nullptr;
  const ElfW(Rela)* rela = nullptr;
  size_t pltrelsz = 0;
  size_t relasz = 0;
  for (; dyn->d_tag != DT_NULL; ++dyn) {
    switch (dyn->d_tag) {
      case DT_STRTAB:
        strtab = reinterpret_cast<const char*>(ResolveDynPtr(info->dlpi_addr, dyn->d_un.d_ptr));
        break;
      case DT_SYMTAB:
        symtab = reinterpret_cast<const ElfW(Sym)*>(ResolveDynPtr(info->dlpi_addr, dyn->d_un.d_ptr));
        break;
      case DT_JMPREL:
        jmprel = reinterpret_cast<const ElfW(Rela)*>(ResolveDynPtr(info->dlpi_addr, dyn->d_un.d_ptr));
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      case DT_RELA:
        rela = reinterpret_cast<const ElfW(Rela)*>(ResolveDynPtr(info->dlpi_addr, dyn->d_un.d_ptr));
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }
  PatchModuleRelocs(info->dlpi_addr, jmprel, pltrelsz / sizeof(ElfW(Rela)), symtab, strtab,
                    relro_start, relro_end);
  PatchModuleRelocs(info->dlpi_addr, rela, relasz / sizeof(ElfW(Rela)), symtab, strtab,
                    relro_start, relro_end);
  return 0;
}

void NativePatchAllModules() {
  std::lock_guard<std::mutex> guard(g_native_patch_lock);
  dl_iterate_phdr(&NativePatchModuleCb, nullptr);
}

// Re-patches all modules a bounded number of times over the first few seconds after install. This
// catches libraries loaded after the initial sweep (the protector's own .so, pulled in via
// System.loadLibrary during app startup), which is why dlopen itself is not hooked. Each sweep is
// idempotent - PatchGotSlot skips slots already pointing at our replacement - so repeating is cheap
// and safe against concurrent callers.
void* NativeRepatchThread(void* /*arg*/) {
  for (int i = 0; i < 100; ++i) {
    usleep(50 * 1000);  // 50ms between sweeps; 100 sweeps span ~5s, covering startup lib loads
    NativePatchAllModules();
  }
  return nullptr;
}

// Resolves the real libc implementations directly (dlsym), once, before any GOT is patched. Using
// dlsym - not the current GOT contents - avoids capturing an unresolved lazy-binding PLT stub, which
// would make our passthrough recurse into the hook. Stored with release so the acquire-loads in the
// replacements see them once a hook is live. dlsym against the already-loaded libc handle, with a
// RTLD_DEFAULT fallback. A symbol that does not resolve leaves its original null, and PatchModuleRelocs
// then skips it (NativeOriginalResolved), so we never run a hook that has no real function to call.
void ResolveNativeOriginals() {
  void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
  auto resolve = [&](const char* sym) -> void* {
    void* p = (libc != nullptr) ? dlsym(libc, sym) : nullptr;
    if (p == nullptr) {
      p = dlsym(RTLD_DEFAULT, sym);
    }
    return p;
  };
  // Bridge the object-pointer dlsym result to a function pointer through uintptr_t (POSIX allows the
  // dlsym cast; the uintptr_t bridge keeps it -Werror-clean).
#define SCANNER_RESOLVE(global, type, name)                                                  \
  (global).store(reinterpret_cast<type>(reinterpret_cast<uintptr_t>(resolve(name))),          \
                 std::memory_order_release)
  SCANNER_RESOLVE(g_real_prop_get, PropGetFn, "__system_property_get");
  SCANNER_RESOLVE(g_real_prop_read, PropReadFn, "__system_property_read");
  SCANNER_RESOLVE(g_real_prop_read_cb, PropReadCbFn, "__system_property_read_callback");
  SCANNER_RESOLVE(g_real_open, OpenFn, "open");
  SCANNER_RESOLVE(g_real_openat, OpenatFn, "openat");
  SCANNER_RESOLVE(g_real_fopen, FopenFn, "fopen");
  SCANNER_RESOLVE(g_real_access, AccessFn, "access");
#undef SCANNER_RESOLVE
  if (libc != nullptr) {
    dlclose(libc);  // RTLD_NOLOAD handle: just drops our extra ref, libc stays mapped
  }
}

// Installs the native interception layer in the current (target) process. Idempotent.
void InstallNativeHooks() {
  bool expected = false;
  if (!g_native_hooks_installed.compare_exchange_strong(expected, true)) {
    return;
  }
  ResolveNativeOriginals();  // must run before any GOT is patched (so no hook is live without its original)
  NativePatchAllModules();
  // A detached worker re-sweeps for a few seconds so libraries loaded during startup are patched too.
  pthread_t repatch_thread;
  if (pthread_create(&repatch_thread, nullptr, &NativeRepatchThread, nullptr) == 0) {
    pthread_detach(repatch_thread);
  }
}
