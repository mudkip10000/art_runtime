/*
 * scanner_hooks syscall layer: a seccomp user-notifier that traps file-path syscalls by NUMBER, so it fires regardless of who issued them.
 *
 * Why a seccomp notifier: the native PLT/GOT layer (scanner_hooks_native.inc) only sees reads that go through libc's exported functions, but hardened RASP (DexProtector, Ant/zoloz) issue their anti-debug / anti-emulator reads via raw `svc` instructions straight to the kernel, touching no libc GOT slot. Trapping by syscall number catches libc and the protector's own inline svc alike.
 *
 * Two independent features, each gated on its own property, installed in the target process only:
 *   - syshook (dalvik.vm.scanner-syshook): serves sanitized /proc copies and returns ENOENT for emulator/root artifacts, so it does change what the trapped thread sees.
 *   - propspoof (dalvik.vm.scanner-propspoof): at install, COW-remaps the inherited bionic property-area mappings private-writable and patches emulator-identifying properties in place. It needs no syscall trap, but runs from InstallSeccompTracer because that is this layer's install hook.
 *
 * Textually included by scanner_hooks.cc inside its anonymous namespace, after the native layer. The Linux/seccomp headers it needs are included at the top of scanner_hooks.cc.
 */

// Path argument is args[1] for every *at syscall we trap (they all take dirfd first). A path longer
// than this is truncated in the log, which is fine for a diagnostic.
constexpr size_t kSeccompPathMax = 512;

// Only these substrings are logged, to keep the trace readable: an app opens thousands of dex/oat/data
// files at startup that are irrelevant to RASP. Everything a root/emulator/debug check would read
// lives under one of these.
const char* const kSeccompInterest[] = {
    "/proc", "/sys", "/dev", "/system/bin", "/system/xbin", "/system/sbin", "/sbin", "/vendor/bin",
    "/data/local", "/magisk", "/su", "/busybox", "/supersu", "/xposed", "/frida", "/substrate",
    "qemu", "goldfish", "ranchu", "/root", "/.ext", "mountinfo", "mounts", "maps", "status",
    "cpuinfo", "tcp", "/init", "selinux", "/default.prop", "build.prop",
};

bool SeccompPathInteresting(const char* path) {
  if (path[0] == '\0') {
    return true;  // unreadable path: log it, it may be the interesting one
  }
  for (const char* needle : kSeccompInterest) {
    if (std::strstr(path, needle) != nullptr) {
      return true;
    }
  }
  return false;
}

// Reads a C string out of this process's own memory without faulting on a bad pointer: process_vm_readv
// returns -EFAULT instead of raising SIGSEGV, unlike a direct dereference. Reads only up to the end of
// the page the pointer starts in, so a one-shot read never straddles into an unmapped neighbour.
void SeccompReadPath(uintptr_t addr, char* out, size_t out_size) {
  out[0] = '\0';
  if (addr == 0 || out_size == 0) {
    return;
  }
  // Read page-by-page: each process_vm_readv stops at a page boundary so a single call can never
  // straddle into an unmapped neighbour and fault, but we keep going into the next page until we hit
  // the NUL terminator. Capping at the first page boundary (as the original did) would truncate any
  // path whose string crosses a page, which then fails the exact redirect/deny match and silently
  // serves the real file - a layout-dependent, intermittent bypass failure.
  size_t pagesz = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  size_t total = 0;
  while (total + 1 < out_size) {
    uintptr_t cur = addr + total;
    size_t to_page_end = pagesz - (cur & (pagesz - 1));
    size_t want = (out_size - 1) - total;
    if (want > to_page_end) {
      want = to_page_end;
    }
    struct iovec local = {out + total, want};
    struct iovec remote = {reinterpret_cast<void*>(cur), want};
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (n <= 0) {
      break;  // unmapped or error: keep whatever we have so far
    }
    void* nul = std::memchr(out + total, '\0', static_cast<size_t>(n));
    total += static_cast<size_t>(n);
    if (nul != nullptr) {
      return;  // out already holds the NUL
    }
    if (static_cast<size_t>(n) < want) {
      break;  // short read: stop
    }
  }
  out[(total < out_size) ? total : (out_size - 1)] = '\0';
}

const char* SeccompSyscallName(int nr) {
#ifdef __NR_openat
  if (nr == __NR_openat) {
    return "openat";
  }
#endif
#ifdef __NR_openat2
  if (nr == __NR_openat2) {
    return "openat2";
  }
#endif
#ifdef __NR_faccessat
  if (nr == __NR_faccessat) {
    return "faccessat";
  }
#endif
#ifdef __NR_faccessat2
  if (nr == __NR_faccessat2) {
    return "faccessat2";
  }
#endif
#ifdef __NR_readlinkat
  if (nr == __NR_readlinkat) {
    return "readlinkat";
  }
#endif
#ifdef __NR_newfstatat
  if (nr == __NR_newfstatat) {
    return "newfstatat";
  }
#endif
#ifdef __NR_statx
  if (nr == __NR_statx) {
    return "statx";
  }
#endif
  return "syscall";
}

// SECCOMP_ADDFD_FLAG_SEND (Linux 5.14) atomically installs the fd and completes the notification.
#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

std::atomic<int> g_seccomp_notify_fd{-1};

// /proc files pre-opened before the filter goes up, so the supervisor can re-read the real content
// with lseek+read (neither is trapped) instead of openat (which is, and would deadlock the supervisor
// against its own notification). procfs regenerates the content on lseek-to-0 + read.
int g_proc_maps_fd = -1;
int g_proc_smaps_fd = -1;
int g_proc_status_fd = -1;

bool ReadWholeFileFromFd(int fd, std::string* out) {
  out->clear();
  if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0) {
    return false;
  }
  std::vector<char> buf(4096);
  for (;;) {
    ssize_t n = read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      break;
    }
    out->append(buf.data(), static_cast<size_t>(n));
  }
  return true;
}

// Generic prefix test, used by the /proc/self/maps path matching in ApplyPropSpoof
bool ScannerStrStartsWith(std::string_view s, const char* prefix) {
  size_t n = std::strlen(prefix);
  return s.size() >= n && std::memcmp(s.data(), prefix, n) == 0;
}

// ---------------------------------------------------------------------------
// Property spoof: in-process COW patch of the inherited bionic property area (dalvik.vm.scanner-propspoof)
// ---------------------------------------------------------------------------
// Emulator-identifying system properties (ro.boot.hardware=ranchu, ro.kernel.qemu=1, ...) are read natively from the mmap'd bionic property area, below any trappable syscall, so neither the managed rules nor a syscall interception of a "read" can reach the consumed value. libc inherits the property-area mappings from the zygote (mapped at preload, before fork) and never re-opens the backing SELinux context files under /dev/__properties__/, so redirecting an openat never fires - there is no open to redirect. Instead, at install we replace each inherited read-only shared context mapping with a private writable COW copy at the SAME virtual address (mmap MAP_PRIVATE | MAP_FIXED over it from the backing file), then patch the target prop_info values directly in that private copy. libc's cached prop_area pointer keeps resolving and now reads our bytes. MAP_PRIVATE means the live context files and every other process are untouched; only this process's own view changes.
// All state below is touched only on the install thread before the supervisor starts, so it needs no lock

// A property to sanitize and the clean, real-device-like value to show. Each value must be <= 91 bytes (bionic PROP_VALUE_MAX - 1). Deliberately NOT ro.hardware.egl / ro.hardware.gralloc (the graphics loader derives from them) and NOT ro.product.brand (already google).
struct PropSpoofTarget {
  const char* name;
  const char* value;
};
const PropSpoofTarget kPropSpoofTargets[] = {
    // SoC / board / qemu identity (ranchu/goldfish/qemu are the hard emulator tells)
    {"ro.boot.hardware", "exynos2100"},
    {"ro.hardware", "exynos2100"},
    {"ro.boot.hardware.vulkan", "exynos2100"},
    {"ro.hardware.vulkan", "exynos2100"},
    {"ro.hardware.power", "exynos2100"},
    {"ro.soc.model", "exynos2100"},
    {"ro.product.board", "exynos2100"},
    {"ro.boot.qemu", "0"},
    {"ro.kernel.qemu", "0"},
    {"ro.build.characteristics", "default"},
    {"ro.bionic.cpu_variant", "cortex-a76"},
    {"ro.bionic.2nd_cpu_variant", "cortex-a55"},
    {"dalvik.vm.isa.arm64.variant", "cortex-a76"},
    // serials (the stock emulator serial literally contains EMULATOR)
    {"ro.serialno", "2A101FDH20001X"},
    {"ro.boot.serialno", "2A101FDH20001X"},
    // product model / name / device, across every partition namespace (all stock-emulator sdk_gphone64_arm64/generic)
    {"ro.product.model", "pixel"},
    {"ro.product.name", "pixel"},
    {"ro.product.device", "pixel"},
    {"ro.product.odm.model", "pixel"},
    {"ro.product.odm.name", "pixel"},
    {"ro.product.product.model", "pixel"},
    {"ro.product.product.name", "pixel"},
    {"ro.product.system.device", "pixel"},
    {"ro.product.system_dlkm.model", "pixel"},
    {"ro.product.system_dlkm.name", "pixel"},
    {"ro.product.system_ext.model", "pixel"},
    {"ro.product.system_ext.name", "pixel"},
    {"ro.product.vendor.model", "pixel"},
    {"ro.product.vendor.name", "pixel"},
    {"ro.product.vendor_dlkm.model", "pixel"},
    {"ro.product.vendor_dlkm.name", "pixel"},
    // build descriptors: flavor/product/description/display plus the fingerprint in every partition copy (kept identical to kFingerprint so managed Build.FINGERPRINT and the native props agree)
    {"ro.build.flavor", "exynos2100-user"},
    {"ro.build.product", "exynos2100"},
    {"ro.build.description", "exynos2100-user 14 UP1A.231005.007 10000000 release-keys"},
    {"ro.build.display.id", "UP1A.231005.007"},
    {"ro.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.odm.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.product.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.system.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.system_ext.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.vendor.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
    {"ro.bootimage.build.fingerprint", "google/exynos2100/pixel:14/UP1A.231005.007/10000000:user/release-keys"},
};

// One /proc/self/maps row, keeping the pathname: we need it to open the context file backing a prop_info for the COW remap, and the [start,end) to match a prop_info to its mapping and bound-check the patch
struct PropSpoofMapRow {
  uintptr_t start;
  uintptr_t end;
  std::string path;
};

// Used at install to read /proc/self/maps while openat still works
bool PropSpoofReadFile(const char* path, std::string* out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  bool ok = ReadWholeFileFromFd(fd, out);
  close(fd);
  return ok;
}

void PropSpoofParseMaps(const std::string& content, std::vector<PropSpoofMapRow>* rows) {
  const char* p = content.c_str();
  while (*p != '\0') {
    char* endp = nullptr;
    uintptr_t start = static_cast<uintptr_t>(strtoull(p, &endp, 16));
    if (endp == p || *endp != '-') {
      while (*p != '\0' && *p != '\n') {
        ++p;
      }
      if (*p == '\n') {
        ++p;
      }
      continue;
    }
    p = endp + 1;
    uintptr_t end = static_cast<uintptr_t>(strtoull(p, &endp, 16));
    if (endp == p) {
      while (*p != '\0' && *p != '\n') {
        ++p;
      }
      if (*p == '\n') {
        ++p;
      }
      continue;
    }
    p = endp;
    const char* eol = p;
    while (*eol != '\0' && *eol != '\n') {
      ++eol;
    }
    // The pathname is the first '/' (file-backed) or '[' (special region); the offset/dev/inode fields between perms and the path never contain either character
    const char* path = nullptr;
    for (const char* q = p; q < eol; ++q) {
      if (*q == '/' || *q == '[') {
        path = q;
        break;
      }
    }
    PropSpoofMapRow row;
    row.start = start;
    row.end = end;
    if (path != nullptr) {
      row.path.assign(path, static_cast<size_t>(eol - path));
    }
    rows->push_back(std::move(row));
    p = (*eol == '\n') ? eol + 1 : eol;
  }
}

// Patches the bionic prop_info at `addr` (now inside a private writable COW page) to carry `value`, following bionic's property seqlock write order so a concurrent reader (an ART thread, or the RASP itself, since DoInstall can run during bindApplication with threads live) never observes the new length over stale value bytes: publish a dirty serial, write the value, then publish the final serial last, with release ordering between the steps. prop_info is { uint32 serial; char value[92]; char name[]; }; only those 96 bytes are touched so the serialized trie and every node offset stay valid. Returns false (skip, fail-safe) if the value cannot fit or the 96-byte {serial, value} slot would run past `map_end`.
bool PropSpoofPatch(char* addr, uintptr_t map_end, const char* value) {
  constexpr size_t kSerialSize = 4;
  constexpr size_t kValueMax = 92;  // bionic PROP_VALUE_MAX
  size_t clean_len = std::strlen(value);
  if (clean_len > kValueMax - 1) {
    return false;
  }
  if (reinterpret_cast<uintptr_t>(addr) + kSerialSize + kValueMax > map_end) {
    return false;
  }
  // serial layout: bits 24..31 = value length, bit 0 = dirty, bits 1..23 = change counter (prop_info is 4-byte aligned in the prop_area, so the uint32 serial is a valid atomic target)
  uint32_t* serialp = reinterpret_cast<uint32_t*>(addr);
  uint32_t old_serial = __atomic_load_n(serialp, __ATOMIC_RELAXED);
  __atomic_store_n(serialp, old_serial | 1u, __ATOMIC_RELEASE);  // mark dirty first so a reader caught in the window retries rather than splicing a new length over old bytes
  char* slot = addr + kSerialSize;
  std::memset(slot, 0, kValueMax);
  std::memcpy(slot, value, clean_len);  // NUL terminator already present from the memset
  uint32_t new_serial = (static_cast<uint32_t>(clean_len) << 24) | (((old_serial & 0x00FFFFFEu) + 2u) & 0x00FFFFFEu);  // new length, dirty cleared, counter bumped
  __atomic_store_n(serialp, new_serial, __ATOMIC_RELEASE);  // publish last: the release store orders the value writes ahead of the visible serial
  return true;
}

// Runs at install, in the target process only, before the seccomp filter goes up (openat still works here, so the backing context files can be reopened and remapped)
// The __system_property_find pointer is opaque: only its address is used, never dereferenced as a C++ object
// Every failure path (prop absent, no backing mapping, open fail, mmap fail, slot out of range) skips that item without crashing
void ApplyPropSpoof() {
  std::string maps;
  if (!PropSpoofReadFile("/proc/self/maps", &maps)) {
    if (g_verbose) {
      LOG(ERROR) << "scanner-propspoof: cannot read /proc/self/maps; propspoof disabled";
    }
    return;
  }
  std::vector<PropSpoofMapRow> rows;
  PropSpoofParseMaps(maps, &rows);
  // Each target resolved to its prop_info address and the context mapping that backs it. row points into `rows`, which is not modified after this parse, so the pointer stays valid.
  struct PropSpoofHit {
    uintptr_t addr;
    const char* name;
    const char* value;
    const PropSpoofMapRow* row;
  };
  std::vector<PropSpoofHit> hits;
  for (const PropSpoofTarget& target : kPropSpoofTargets) {
    const prop_info* pi = __system_property_find(target.name);
    if (pi == nullptr) {
      continue;  // property absent on this device: nothing to spoof
    }
    uintptr_t addr = reinterpret_cast<uintptr_t>(pi);
    const PropSpoofMapRow* row = nullptr;
    for (const PropSpoofMapRow& r : rows) {
      if (addr >= r.start && addr < r.end && ScannerStrStartsWith(r.path, "/dev/__properties__/")) {
        row = &r;
        break;
      }
    }
    if (row == nullptr) {
      continue;  // prop_info not backed by a known context mapping
    }
    hits.push_back({addr, target.name, target.value, row});
  }
  // Convert each distinct backing context mapping to a private writable COW copy at its own VA, so libc's cached prop_area pointer keeps resolving while the pages become patchable. `attempted` makes each mapping remap once (several targets can live in one context); `remapped` holds the start of every mapping that succeeded, so props whose mapping stayed shared read-only are left unpatched below rather than faulting.
  std::unordered_set<uintptr_t> attempted;
  std::unordered_set<uintptr_t> remapped;
  for (const PropSpoofHit& hit : hits) {
    if (!attempted.insert(hit.row->start).second) {
      continue;
    }
    size_t len = static_cast<size_t>(hit.row->end - hit.row->start);
    int fd = open(hit.row->path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      if (g_verbose) {
        LOG(ERROR) << "scanner-propspoof: cannot open context '" << hit.row->path << "' errno="
                   << errno;
      }
      continue;
    }
    // MAP_PRIVATE | PROT_WRITE on an O_RDONLY fd is allowed: writes go to private COW pages, never the file. MAP_FIXED replaces the inherited shared mapping in place, keeping every prop_info VA resolved above valid.
    void* res = mmap(reinterpret_cast<void*>(hit.row->start), len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED, fd, 0);
    close(fd);
    if (res == MAP_FAILED || res != reinterpret_cast<void*>(hit.row->start)) {
      if (g_verbose) {
        LOG(ERROR) << "scanner-propspoof: COW remap failed for '" << hit.row->path << "' errno="
                   << errno;
      }
      continue;
    }
    remapped.insert(hit.row->start);
  }
  for (const PropSpoofHit& hit : hits) {
    if (remapped.find(hit.row->start) == remapped.end()) {
      continue;  // backing mapping was not remapped writable
    }
    if (!PropSpoofPatch(reinterpret_cast<char*>(hit.addr), hit.row->end, hit.value)) {
      if (g_verbose) {
        LOG(ERROR) << "scanner-propspoof: patch out of range for '" << hit.name << "'";
      }
      continue;
    }
    if (g_verbose) {
      LOG(INFO) << "scanner-propspoof: patched '" << hit.name << "' -> '" << hit.value << "'";
    }
  }
}

// For an openat we serve a sanitized copy of, returns the matching pre-opened fd, else -1.
int SeccompRedirectFdFor(const char* path) {
  if (std::strcmp(path, "/proc/self/maps") == 0) {
    return g_proc_maps_fd;
  }
  if (std::strcmp(path, "/proc/self/smaps") == 0) {
    return g_proc_smaps_fd;
  }
  if (std::strcmp(path, "/proc/self/status") == 0) {
    return g_proc_status_fd;
  }
  return -1;
}

// Paths we make disappear (ENOENT): the native layer's root/hook deny list. Deliberately NOT the /dev/goldfish* nodes (the graphics stack in the app process uses them, so a process-wide deny would break rendering) and no longer any /dev/__properties__ context, since an ENOENT on a property context a real device also has is itself an emulator tell.
bool SeccompDenyPath(const char* path) {
  return PathInList(path, kDenyPaths, sizeof(kDenyPaths) / sizeof(kDenyPaths[0]));
}

// Delivers a notification response, retrying on EINTR. Returns true once the notification is resolved
// (either delivered, or the trapped thread already died -> ENOENT). Returns false only on a genuine
// failure, so the caller can fall back rather than leave the trapped thread blocked forever (there is
// no kernel timeout for SECCOMP_RET_USER_NOTIF, so a dropped response is a permanent app hang).
bool SeccompNotifSend(int fd, struct seccomp_notif_resp* resp) {
  for (;;) {
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == 0) {
      return true;
    }
    if (errno == EINTR) {
      continue;
    }
    return errno == ENOENT;  // trapped thread gone: nothing left to answer
  }
}

// Services one seccomp notification: read the trapped syscall's path, log it if relevant, then answer
// CONTINUE so the kernel runs the real syscall unchanged. The trapped thread is blocked until we
// answer, so this must never itself issue a trapped syscall (logging uses an already-connected logd
// socket, process_vm_readv and ioctl are not in the trap set).
void* SeccompSupervisor(void* /*arg*/) {
  int fd = g_seccomp_notify_fd.load(std::memory_order_acquire);
  struct seccomp_notif_sizes sizes {};
  if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0u, &sizes) != 0) {
    return nullptr;
  }
  std::vector<char> reqbuf(sizes.seccomp_notif);
  std::vector<char> respbuf(sizes.seccomp_notif_resp);
  auto* req = reinterpret_cast<struct seccomp_notif*>(reqbuf.data());
  auto* resp = reinterpret_cast<struct seccomp_notif_resp*>(respbuf.data());
  for (;;) {
    std::memset(req, 0, reqbuf.size());
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
      if (errno == EINTR) {
        continue;
      }
      break;  // listener closed: the process is going away
    }
    int nr = static_cast<int>(req->data.nr);
    char path[kSeccompPathMax];
    // Confirm the notification is still live before touching the trapped thread's memory: if it died,
    // the id is stale and the address may be gone.
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0) {
      SeccompReadPath(static_cast<uintptr_t>(req->data.args[1]), path, sizeof(path));
    } else {
      path[0] = '\0';
    }
    const char* verb = "continue";
    // Spoof mode: for syshook, serve a sanitized copy of the sensitive /proc files and make emulator/root artifacts disappear, and continue everything else. ADDFD with _SEND completes the notification itself, so in that one branch we must not also NOTIF_SEND.
    bool answered = false;
    if (g_cat_syshook) {
      bool is_openat = false;
#ifdef __NR_openat
      is_openat = (nr == __NR_openat);
#endif
      int rfd = is_openat ? SeccompRedirectFdFor(path) : -1;
      if (rfd >= 0) {
        std::string real;
        std::string san;
        if (ReadWholeFileFromFd(rfd, &real) && SanitizeContent(path, real, &san)) {
          int mem = MakeMemContentFd(san);
          if (mem < 0) {
            if (g_verbose) {
              LOG(ERROR) << "scanner-syscall: memfd failed for '" << path << "' errno=" << errno;
            }
          } else {
            struct seccomp_notif_addfd addfd {};
            addfd.id = req->id;
            addfd.flags = SECCOMP_ADDFD_FLAG_SEND;
            addfd.srcfd = static_cast<__u32>(mem);
            long newfd = ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
            if (newfd >= 0) {
              answered = true;
              verb = "redirect";
            } else {
              // Kernel without SECCOMP_ADDFD_FLAG_SEND (pre-5.14): add the fd, then answer with it
              int send_errno = errno;
              struct seccomp_notif_addfd addfd2 {};
              addfd2.id = req->id;
              addfd2.srcfd = static_cast<__u32>(mem);
              newfd = ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd2);
              if (newfd >= 0) {
                std::memset(resp, 0, respbuf.size());
                resp->id = req->id;
                resp->val = newfd;
                answered = SeccompNotifSend(fd, resp);
                verb = "redirect";
              } else if (g_verbose) {
                LOG(ERROR) << "scanner-syscall: ADDFD failed '" << path << "' send_errno=" << send_errno
                           << " plain_errno=" << errno;
              }
            }
            close(mem);
          }
        } else if (g_verbose) {
          LOG(ERROR) << "scanner-syscall: read/sanitize failed '" << path << "' rfd=" << rfd;
        }
      } else if (SeccompDenyPath(path)) {
        std::memset(resp, 0, respbuf.size());
        resp->id = req->id;
        resp->error = -ENOENT;
        answered = SeccompNotifSend(fd, resp);
        verb = "deny";
      }
    }
    if (!answered) {
      std::memset(resp, 0, respbuf.size());
      resp->id = req->id;
      resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
      SeccompNotifSend(fd, resp);  // best-effort; if the trapped thread is gone there is nothing to do
    }
    if (g_verbose && SeccompPathInteresting(path)) {
      LOG(INFO) << "scanner-syscall: " << SeccompSyscallName(nr) << " tid=" << req->pid << " path='"
                << path << "' -> " << verb;
    }
  }
  return nullptr;
}

void SeccompAddTrap(std::vector<struct sock_filter>* prog, uint32_t nr) {
  prog->push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
  prog->push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
}

// Installs the user-notify filter in this (target) process and starts the supervisor. Fail-safe: any
// failure logs and returns, leaving the process untraced rather than broken.
void InstallSeccompTracer() {
  if (g_verbose) {
    // Also pre-warms the logd connection before the filter, so the supervisor's own logging never has
    // to open the socket (which would trap) while servicing a notification.
    LOG(INFO) << "scanner-syscall: installing seccomp syscall filter";
  }
  // Pre-open the files the spoofer serves sanitized, while openat still works (it is about to be trapped); the supervisor re-reads these with lseek+read, which is never trapped.
  if (g_cat_syshook) {
    g_proc_maps_fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    g_proc_smaps_fd = open("/proc/self/smaps", O_RDONLY | O_CLOEXEC);
    g_proc_status_fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  }
  if (g_cat_propspoof) {
    ApplyPropSpoof();  // remap the inherited property-context mappings COW-private and patch the emulator props in place, while mmap still works
  }
  if (!g_cat_syshook) {
    return;  // propspoof is patched in place above and needs no runtime trap; only syshook needs the filter + supervisor, so a propspoof-only process pays zero per-syscall cost
  }
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // app zygote already sets it; harmless to repeat
  std::vector<struct sock_filter> prog;
  prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));
#ifdef __NR_openat
  SeccompAddTrap(&prog, __NR_openat);
#endif
#ifdef __NR_openat2
  SeccompAddTrap(&prog, __NR_openat2);
#endif
#ifdef __NR_faccessat
  SeccompAddTrap(&prog, __NR_faccessat);
#endif
#ifdef __NR_faccessat2
  SeccompAddTrap(&prog, __NR_faccessat2);
#endif
  // Deliberately NOT trapping newfstatat/statx: they fire on every file stat during class loading, so
  // trapping them routes thousands of calls through the supervisor and slows the process enough for a
  // RASP timing check to notice (intermittently). We only redirect openat and deny via openat/access,
  // and the paths we deny that actually exist (the qemu property contexts) are probed with
  // faccessat/openat, not stat - so dropping the stat traps costs no coverage.
  prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  struct sock_fprog fprog {
    static_cast<unsigned short>(prog.size()), prog.data()
  };
  long fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
  if (fd < 0) {
    if (g_verbose) {
      LOG(ERROR) << "scanner-syscall: seccomp NEW_LISTENER failed errno=" << errno;
    }
    return;
  }
  g_seccomp_notify_fd.store(static_cast<int>(fd), std::memory_order_release);
  pthread_t th;
  if (pthread_create(&th, nullptr, &SeccompSupervisor, nullptr) != 0) {
    if (g_verbose) {
      LOG(ERROR) << "scanner-syscall: supervisor thread create failed";
    }
    close(static_cast<int>(fd));
    g_seccomp_notify_fd.store(-1, std::memory_order_release);
    return;
  }
  pthread_detach(th);
  if (g_verbose) {
    LOG(INFO) << "scanner-syscall: filter active (" << prog.size() << " BPF insns)";
  }
}
