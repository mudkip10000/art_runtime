/*
 * Hardcoded method/field interception rules.
 *
 * A fixed table of framework methods and fields is intercepted inside the target app process to
 * substitute a return value or spoof a field value.
 *
 * Configuration (system properties set by the scanner during device setup):
 *   - dalvik.vm.scanner-target       : package of the app to instrument (required)
 *   - dalvik.vm.scanner-rasp         : enable rasp_bypass rules           (bool)
 *   - dalvik.vm.scanner-ssl          : enable ssl_bypass rules            (bool)
 *   - dalvik.vm.scanner-package      : enable package_manipulation rules  (bool)
 *   - dalvik.vm.scanner-secure-flag  : enable secure_flag_bypass rules    (bool)
 *
 * Mechanism:
 *   - At app-process start (Runtime::InitNonZygoteOrPostFork) the properties are read; if a target
 *     and at least one category are set, a lightweight AppInfoCallback is registered. Nothing else
 *     happens, so non-target processes carry no overhead.
 *   - When the process package becomes known (AppInfoCallback::SetCurrentProcessName) and matches
 *     the target, the hooks are installed: non-standard exits enabled, a ClassLoadCallback and an
 *     instrumentation listener registered, the process forced into the interpreter, and all
 *     already-loaded classes swept. Only rules of enabled categories are applied.
 *   - A targeted class has its spoofed fields set once and its targeted methods recorded.
 *   - MethodEntered matches the rule and, on a match, forces an early return by setting force-pop
 *     on the top shadow frame and stashing the value; NonStandardExitPopped then supplies it. When
 *     a rule's predicate does not match, the method runs unmodified.
 */

#ifndef ART_RUNTIME_SCANNER_HOOKS_H_
#define ART_RUNTIME_SCANNER_HOOKS_H_

namespace art {

class ScannerHooks {
 public:
  // Reads the scanner-* system properties and records the target/category config. Called once per
  // process at post-fork (Runtime::InitNonZygoteOrPostFork), where the process is not yet
  // specialized: /proc/self/cmdline is still "zygote" and the comm name is truncated to 15 chars,
  // so the package cannot be reliably matched here. The actual install therefore happens later from
  // OnProcessPackageName(). A no-op in every other process.
  static void Install();

  // Called when the full, untruncated process package name becomes known
  // (dalvik.system.VMRuntime.setProcessPackageName, during bindApplication). If it matches the
  // configured target and a category is enabled, installs the hooks. This is the reliable gate:
  // it runs for every app process, scanner-driven or not, with the real package name. A no-op if
  // not configured, not the target, or already installed. Call with the thread in kNative state
  // (the JNI native context).
  static void OnProcessPackageName(const char* package_name);
};

}  // namespace art

#endif  // ART_RUNTIME_SCANNER_HOOKS_H_
