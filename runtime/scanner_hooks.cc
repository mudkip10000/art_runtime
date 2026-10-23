/*
 * Hardcoded method/field interception rules. See scanner_hooks.h for the design overview.
 *
 * The table covers method calls that return a constant (optionally gated by a constant String
 * argument) and android.os.Build fields spoofed to a constant.
 */

#include "scanner_hooks.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sys/prctl.h>

#include <android-base/file.h>
#include <android-base/properties.h>

#include "art_field-inl.h"
#include "art_method-inl.h"
#include "base/logging.h"
#include "class_linker.h"
#include "dex/primitive.h"
#include "gc/scoped_gc_critical_section.h"
#include "handle_scope-inl.h"
#include "instrumentation.h"
#include "interpreter/shadow_frame.h"
#include "stack.h"
#include "jni/java_vm_ext.h"
#include "jni/jni_internal.h"
#include "jvalue-inl.h"
#include "mirror/class-inl.h"
#include "mirror/iftable.h"
#include "mirror/object-inl.h"
#include "mirror/object_array-inl.h"
#include "mirror/object_array-alloc-inl.h"
#include "mirror/array-inl.h"
#include "mirror/string.h"
#include "runtime.h"
#include "runtime_callbacks.h"
#include "scoped_thread_state_change-inl.h"
#include "stack_reference.h"
#include "thread.h"
#include "thread-inl.h"
#include "thread_list.h"

namespace art {

namespace {

// ---------------------------------------------------------------------------
// Generic string constants
// ---------------------------------------------------------------------------
// Plumbing used by the engine helpers below regardless of any particular rule. Constants tied to a
// specific rule's behaviour (spoofed values, the fields a mutate rule rewrites, an action's target
// object) live with the rules in scanner_hooks_rules.inc and scanner_hooks_scripts.inc instead.

// java.lang.String type descriptor, used to resolve String fields by (name, type).
constexpr const char* kStringDescriptor = "Ljava/lang/String;";

// android.os.Debug.waitForDebugger(), resolved once for the debugger-detection gate.
constexpr const char* kDebugDescriptor = "Landroid/os/Debug;";
constexpr const char* kWaitForDebuggerName = "waitForDebugger";
constexpr const char* kVoidNoArgsSignature = "()V";

// Process names the zygote carries before specialization (not yet a real app process).
constexpr const char* kZygoteProcName = "zygote";
constexpr const char* kZygote64ProcName = "zygote64";

// System-property keys that configure these hooks, read once at install.
constexpr const char* kPropTarget = "dalvik.vm.scanner-target";
constexpr const char* kPropRasp = "dalvik.vm.scanner-rasp";
constexpr const char* kPropSsl = "dalvik.vm.scanner-ssl";
constexpr const char* kPropPackage = "dalvik.vm.scanner-package";
constexpr const char* kPropSecureFlag = "dalvik.vm.scanner-secure-flag";
constexpr const char* kPropDebugger = "dalvik.vm.scanner-debugger";
constexpr const char* kPropVerbose = "dalvik.vm.scanner-verbose";

// ---------------------------------------------------------------------------
// Rule table
// ---------------------------------------------------------------------------

// The kind of protection a rule defeats. Groups rules so whole classes can be reasoned about or
// toggled together.
enum class RuleCategory {
  kRaspBypass,           // root / emulator / tamper detection
  kSslBypass,            // TLS trust and hostname verification
  kPackageManipulation,  // installer / package identity, incl. the fabricated Google-package
                         // getPackageInfo response (built off an embedded Google signing cert)
  kSecureFlagBypass,     // FLAG_SECURE and screenshot restrictions
  kDebuggerBypass,       // debugger detection; applied only while a JDWP debugger is attached
};

enum class ActionKind {
  kConstBool,       // force-return a boolean
  kConstInt,        // force-return an int
  kConstString,     // force-return a String (interned at install time)
  kConstNull,       // force-return null (reference type)
  kConstVoid,       // force-return from a void method (suppresses the body, throws nothing)
  kConstEmptyList,  // force-return java.util.Collections.EMPTY_LIST
  kFieldSetBool,    // set a boolean field once at class-prepare
  kFieldSetString,  // set a String field once at class-prepare
  kCallbackMutate,  // run a native callback (int_value selects it) that mutates arg/this state,
                    // then let the method run unmodified (no force-return)
  kCallbackReturn,  // run a native callback (int_value selects it) that COMPUTES a return value
                    // (may invoke managed code); on success force-return it, on failure no-op
  kCallbackMutateReturn,  // on MethodExited, run a native callback (int_value selects it) that
                          // mutates the returned object in place; method otherwise runs normally
};

// Callback ids for kCallbackMutate / kCallbackReturn / kCallbackMutateReturn rules (Rule::int_value).
enum CallbackId {
  kCbBindServiceSpoof = 1,  // rewrite the Intent's target package on a Play Integrity / SafetyNet bind
  kCbClearSecureFlag = 2,   // clear FLAG_SECURE from a Window.addFlags/setFlags int argument
  // kCallbackReturn (compute + force-return):
  kCbCheckServerTrustedList = 3,  // X509TrustManager.checkServerTrusted(List): return Arrays.asList(chain)
  kCbWebViewProceed = 4,          // WebViewClient.onReceivedSslError: handler.proceed(), return void
  kCbFakeGooglePackageInfo = 5,   // getPackageInfo("com.android.vending"/gms): return fake Google PackageInfo
  // kCallbackMutate (mutate state, then run):
  kCbSslPeerUnverifiedStepOut = 6, // SSLPeerUnverifiedException.<init>: force the void-returning caller to return
  kCbProcessBuilderSpoofCommand = 7,  // ProcessBuilder.start: rewrite the command list so shell-based
                                      // RASP probes (which su, getprop <key>, su) get benign faked output
  // kCallbackMutateReturn (mutate returned object on exit):
  kCbClearApplicationInfoDebuggable = 8,  // ApplicationInfo returned by getApplicationInfo: clear FLAG_DEBUGGABLE
  // kCallbackReturn (mutate state, then force-return void):
  kCbJarFileSkipVerifier = 9,  // JarFile.maybeInstantiateVerifier: disable JAR signature verification
                               // (verify=false, jv=null) and skip the method body
};

struct Rule {
  RuleCategory category;
  const char* class_descriptor;  // e.g. "Landroid/os/Debug;"
  const char* member_name;       // method or field name (exact; patterns are enumerated)
  bool is_field;

  // Optional argument predicate (methods only). If arg_position >= 0, the rule fires only when
  // the String argument at that logical position equals one of arg_values[0..arg_count).
  int arg_position;
  const char* const* arg_values;
  int arg_count;

  ActionKind action;
  bool bool_value;
  int32_t int_value;
  const char* string_value;  // kConstString / kFieldSetString

  // Optional `this`-field predicate (instance methods only). If non-null, the rule fires only
  // when the String value of this.<this_field> equals one of arg_values[0..arg_count). Declared
  // after string_value so rows that stop earlier default it to nullptr.
  const char* this_field;

  // If true, class_descriptor is matched against the prepared class's whole hierarchy
  // (superclasses + implemented interfaces), so a rule on an interface or base type applies to
  // every implementor/subclass. If false, only the exact class matches.
  bool match_subtypes;

  // If non-zero, restricts a method rule to overloads whose return type shorty is this char
  // ('V' void, 'Z' boolean, 'I' int, 'L' reference, ...). Disambiguates same-named overloads
  // with different return types (e.g. X509TrustManager.checkServerTrusted void vs List).
  char return_shorty;
};

constexpr int kNoArg = -1;

// The rule table and its argument-value arrays are defined in scanner_hooks_rules.inc and textually
// included here, inside the anonymous namespace, so the table can use the file-local enums, Rule
// struct and kNoArg defined above.
#include "scanner_hooks_rules.inc"

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

// Interned String constants, keyed by the table's string_value pointer, held alive as JNI
// global refs created in DoInstall().
std::unordered_map<const char*, jobject> g_interned;  // GUARDED_BY(g_lock)

// Resolved method -> rules that target it. Written at ClassPrepare, read at MethodEntered.
std::unordered_map<ArtMethod*, std::vector<const Rule*>> g_method_rules;  // GUARDED_BY(g_lock)
std::mutex g_lock;

// Methods to deoptimize, collected during the install-time sweep and deoptimized together under the
// install suspend-all. (After install, newly-matched methods are deoptimized inline - see
// ApplyMethodRule.)
std::vector<ArtMethod*> g_pending_deopt;  // GUARDED_BY(g_lock)

// Resolved once at install: android.os.Debug.waitForDebugger(). Used by the debugger-detection
// gate to identify (by pointer, never by descriptor deref) when isDebuggerConnected is being
// called from the framework's wait-for-debugger poll, so that call is not spoofed.
ArtMethod* g_wait_for_debugger = nullptr;  // written once in ResolveWaitForDebugger at install, read racily after
std::atomic<bool> g_installing{false};    // true during the install-time sweep

std::atomic<bool> g_installed{false};

// Global ref to java.util.Collections.EMPTY_LIST, resolved once at install; null if unresolved.
jobject g_empty_list = nullptr;

// Device API level (ro.build.version.sdk), read once at Install(). Used to pick version-specific
// object shapes in the Google-package spoof (e.g. SigningDetails vs PackageParser.SigningDetails).
int g_sdk_int = 0;

// Configuration read from system properties at ScannerHooks::Install(). Hooks are installed only in
// the process whose package matches g_target_package, and a rule applies only if its category is
// enabled. The backing properties, e.g.:
//   dalvik.vm.scanner-target com.the.app
//   dalvik.vm.scanner-rasp true ; dalvik.vm.scanner-ssl true
std::string g_target_package;      // dalvik.vm.scanner-target
bool g_cat_rasp = false;           // dalvik.vm.scanner-rasp
bool g_cat_ssl = false;            // dalvik.vm.scanner-ssl
bool g_cat_pkg = false;            // dalvik.vm.scanner-package
bool g_cat_secure = false;         // dalvik.vm.scanner-secure-flag
bool g_cat_debugger = false;       // dalvik.vm.scanner-debugger (deferred until a debugger attaches)
bool g_verbose = false;            // dalvik.vm.scanner-verbose (log each rule that fires)

bool CategoryEnabled(RuleCategory c) {
  switch (c) {
    case RuleCategory::kRaspBypass: return g_cat_rasp;
    case RuleCategory::kSslBypass: return g_cat_ssl;
    case RuleCategory::kPackageManipulation: return g_cat_pkg;
    case RuleCategory::kSecureFlagBypass: return g_cat_secure;
    case RuleCategory::kDebuggerBypass: return g_cat_debugger;
  }
  return false;
}

bool AnyCategoryEnabled() {
  return g_cat_rasp || g_cat_ssl || g_cat_pkg || g_cat_secure || g_cat_debugger;
}

// Per-thread pending forced returns: MethodEntered pushes, NonStandardExitPopped consumes. The
// two run on the same thread, and t_pending is thread_local, so only this thread touches it.
// For kCallbackReturn the value is computed in MethodEntered and carried here as a JNI global ref
// (cb_ref, an object result) or cb_void (a void result); BuildValue delivers it and releases the ref.
struct PendingReturn {
  const ShadowFrame* frame;
  ArtMethod* method;
  const Rule* rule;
  jobject cb_ref = nullptr;   // kCallbackReturn object result (global ref, released on delivery)
  bool cb_void = false;       // kCallbackReturn void result
};
thread_local std::vector<PendingReturn> t_pending;

// Set while a native callback runs, so managed code it triggers doesn't re-enter the hook.
thread_local bool t_in_hook = false;

jobject InternedFor(const char* key) {
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_interned.find(key);
  return it == g_interned.end() ? nullptr : it->second;
}

// ---------------------------------------------------------------------------
// General frame inspection / modification
// ---------------------------------------------------------------------------
// Rule-agnostic primitives for reading and writing interpreter shadow-frame state (arguments, the
// receiver's fields). The rule action scripts (scanner_hooks_scripts.inc) build on these.

// Reads the String argument at the given logical position of an interpreter frame, or null.
ObjPtr<mirror::String> GetStringArg(ShadowFrame* sf, ArtMethod* method, int logical_pos)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  const uint16_t num_regs = method->DexInstructionData().RegistersSize();
  const uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return nullptr;
  }
  const int first_arg = static_cast<int>(num_regs) - static_cast<int>(ins);
  const bool is_static = method->IsStatic();
  int slot = first_arg + (is_static ? 0 : 1);
  const char* shorty = method->GetShorty();
  if (shorty == nullptr) {
    return nullptr;
  }
  int param = 0;
  for (size_t s = 1; shorty[s] != '\0'; ++s) {
    if (param == logical_pos) {
      if (shorty[s] != 'L') {
        return nullptr;  // predicate positions are always String in the table
      }
      mirror::Object* o = sf->GetVRegReference(slot);
      return (o == nullptr) ? ObjPtr<mirror::String>(nullptr) : o->AsString();
    }
    slot += (shorty[s] == 'J' || shorty[s] == 'D') ? 2 : 1;
    ++param;
  }
  return nullptr;
}

// Reads this.<field_name> as a String for an instance-method interpreter frame, or null.
ObjPtr<mirror::String> GetThisStringField(ShadowFrame* sf, ArtMethod* method, const char* field_name)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  if (method->IsStatic()) {
    return nullptr;
  }
  const uint16_t num_regs = method->DexInstructionData().RegistersSize();
  const uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return nullptr;
  }
  mirror::Object* self_obj = sf->GetVRegReference(static_cast<int>(num_regs) - static_cast<int>(ins));
  if (self_obj == nullptr) {
    return nullptr;
  }
  ArtField* field = self_obj->GetClass()->FindDeclaredInstanceField(field_name, kStringDescriptor);
  if (field == nullptr) {
    return nullptr;
  }
  ObjPtr<mirror::Object> value = field->GetObject(self_obj);
  return (value == nullptr) ? ObjPtr<mirror::String>(nullptr) : value->AsString();
}

// Reads the object argument at the given logical position of an interpreter frame, or null.
mirror::Object* GetArgObject(ShadowFrame* sf, ArtMethod* method, int logical_pos)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  const uint16_t num_regs = method->DexInstructionData().RegistersSize();
  const uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return nullptr;
  }
  const int first_arg = static_cast<int>(num_regs) - static_cast<int>(ins);
  const bool is_static = method->IsStatic();
  int slot = first_arg + (is_static ? 0 : 1);
  const char* shorty = method->GetShorty();
  if (shorty == nullptr) {
    return nullptr;
  }
  int param = 0;
  for (size_t s = 1; shorty[s] != '\0'; ++s) {
    if (param == logical_pos) {
      return (shorty[s] == 'L') ? sf->GetVRegReference(slot) : nullptr;
    }
    slot += (shorty[s] == 'J' || shorty[s] == 'D') ? 2 : 1;
    ++param;
  }
  return nullptr;
}

// Returns the vreg slot of the logical argument at `logical_pos` (any type), or -1. Mirrors the slot
// arithmetic in GetArgObject; used to read/write a primitive argument in place.
int GetArgSlot(ArtMethod* method, int logical_pos) REQUIRES_SHARED(Locks::mutator_lock_) {
  const uint16_t num_regs = method->DexInstructionData().RegistersSize();
  const uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return -1;
  }
  int slot = static_cast<int>(num_regs) - static_cast<int>(ins) + (method->IsStatic() ? 0 : 1);
  const char* shorty = method->GetShorty();
  if (shorty == nullptr) {
    return -1;
  }
  int param = 0;
  for (size_t idx = 1; shorty[idx] != '\0'; ++idx) {
    if (param == logical_pos) {
      return slot;
    }
    slot += (shorty[idx] == 'J' || shorty[idx] == 'D') ? 2 : 1;
    ++param;
  }
  return -1;
}

// Sets this.<field_name> (a String instance field) to `value` on `obj`, if the field exists.
void SetStringField(mirror::Object* obj, const char* field_name, ObjPtr<mirror::String> value)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  ArtField* field = obj->GetClass()->FindDeclaredInstanceField(field_name, kStringDescriptor);
  if (field != nullptr) {
    field->SetObject<false>(obj, value);
  }
}

ObjPtr<mirror::String> GetStringFieldOf(mirror::Object* obj, const char* field_name)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  ArtField* field = obj->GetClass()->FindDeclaredInstanceField(field_name, kStringDescriptor);
  if (field == nullptr) {
    return nullptr;
  }
  ObjPtr<mirror::Object> value = field->GetObject(obj);
  return (value == nullptr) ? ObjPtr<mirror::String>(nullptr) : value->AsString();
}

// Returns the receiver (this) of an instance-method interpreter frame, or null for a static method /
// malformed frame. The receiver is the first incoming vreg (num_regs - ins), as in GetThisStringField.
mirror::Object* GetReceiver(ShadowFrame* sf, ArtMethod* method) REQUIRES_SHARED(Locks::mutator_lock_) {
  if (method->IsStatic()) {
    return nullptr;
  }
  const uint16_t num_regs = method->DexInstructionData().RegistersSize();
  const uint16_t ins = method->DexInstructionData().InsSize();
  if (ins == 0 || ins > num_regs) {
    return nullptr;
  }
  return sf->GetVRegReference(static_cast<int>(num_regs) - static_cast<int>(ins));
}

// Rule action "scripts" (kCallbackMutate bodies) live in a separate file, grouped with the rules
// rather than with the general frame-inspection helpers above. Included here, after those helpers it
// depends on and before the listener that dispatches to it.
#include "scanner_hooks_scripts.inc"

bool InArgValues(const Rule* rule, ObjPtr<mirror::String> s) REQUIRES_SHARED(Locks::mutator_lock_) {
  if (s == nullptr) {
    return false;
  }
  for (int i = 0; i < rule->arg_count; ++i) {
    if (s->Equals(rule->arg_values[i])) {
      return true;
    }
  }
  return false;
}

bool ArgMatches(const Rule* rule, ShadowFrame* sf, ArtMethod* method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  if (rule->this_field != nullptr) {
    return InArgValues(rule, GetThisStringField(sf, method, rule->this_field));
  }
  if (rule->arg_position == kNoArg) {
    return true;
  }
  return InArgValues(rule, GetStringArg(sf, method, rule->arg_position));
}

// True when android.os.Debug.isDebuggerConnected() is being called from
// android.os.Debug.waitForDebugger()'s own spin loop. When a process is started waiting for a
// debugger, the framework's startup gate calls Debug.waitForDebugger(), which polls
// Debug.isDebuggerConnected() until a debugger has attached. Forcing that poll to false would hang
// the process at startup before any app code runs, so this caller is exempted and sees the real
// value; every other caller (the app's own detection checks) gets the spoofed value, whether or
// not a debugger is actually attached.
bool CalledFromWaitForDebugger(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  if (g_wait_for_debugger == nullptr) {
    return false;  // not resolved -> cannot be a waitForDebugger call; spoof normally
  }
  // Scan the WHOLE stack for Debug.waitForDebugger(), not just the immediate caller. The framework's
  // wait-for-debugger startup gate reaches isDebuggerConnected() from inside waitForDebugger()'s spin
  // loop, but the frame directly below the hooked method is not reliably waitForDebugger: deoptimizing
  // isDebuggerConnected leaves a second (quick-stub) frame for the method itself, and transition/
  // runtime frames can sit between it and the real caller, so an immediate-caller check misses it.
  // Match by ArtMethod pointer only -- never call GetName()/GetDeclaringClassDescriptor() here: on
  // some stack shapes a descriptor deref faults (null ArtMethod::ptr_sized_fields_ at 0x10).
  struct WaitForDebuggerFinder final : public StackVisitor {
    explicit WaitForDebuggerFinder(Thread* t)
        : StackVisitor(t, nullptr, StackWalkKind::kIncludeInlinedFrames) {}
    bool VisitFrame() override REQUIRES_SHARED(Locks::mutator_lock_) {
      if (GetMethod() == g_wait_for_debugger) {
        found = true;
        return false;  // found waitForDebugger on the stack; stop walking
      }
      return true;  // keep walking
    }
    bool found = false;
  };
  WaitForDebuggerFinder v(self);
  v.WalkStack();
  return v.found;
}

// ---------------------------------------------------------------------------
// Instrumentation listener
// ---------------------------------------------------------------------------

class ScannerListener final : public instrumentation::InstrumentationListener {
 public:
  void MethodEntered(Thread* thread, ArtMethod* method)
      override REQUIRES_SHARED(Locks::mutator_lock_) {
    if (t_in_hook) {
      return;  // re-entered from a callback's own managed code; ignore
    }
    ShadowFrame* sf = thread->GetManagedStack()->GetTopShadowFrame();
    if (sf == nullptr) {
      return;  // not an interpreter frame; cannot force-return or mutate reliably
    }
    const Rule* matched = nullptr;
    {
      std::lock_guard<std::mutex> guard(g_lock);
      auto it = g_method_rules.find(method);
      if (it == g_method_rules.end()) {
        return;
      }
      for (const Rule* rule : it->second) {
        if (ArgMatches(rule, sf, method)) {
          matched = rule;
          break;
        }
      }
    }
    if (matched == nullptr) {
      return;
    }
    // Debugger-detection rules are deferred past the framework's wait-for-debugger startup gate:
    // a spoofed "not connected" inside Debug.waitForDebugger() would hang a process that was
    // started waiting for a debugger before any app code runs. Only the app's own calls get the
    // spoof.
    if (matched->category == RuleCategory::kDebuggerBypass && CalledFromWaitForDebugger(thread)) {
      if (g_verbose) {
        LOG(INFO) << "scanner: deferred " << matched->class_descriptor << "."
                  << matched->member_name << " (called from Debug.waitForDebugger)";
      }
      return;
    }
    if (g_verbose) {
      LOG(INFO) << "scanner: rule fired " << matched->class_descriptor << "." << matched->member_name;
    }
    if (matched->action == ActionKind::kCallbackMutateReturn) {
      return;  // applied on MethodExited (mutates the returned object), not on entry
    }
    if (matched->action == ActionKind::kCallbackMutate) {
      t_in_hook = true;
      RunMutateCallback(thread, matched, sf, method);
      t_in_hook = false;
      return;  // method runs normally with the mutated (or stepped-out) state
    }
    if (matched->action == ActionKind::kCallbackReturn) {
      // Compute the return value natively (may invoke managed code). On any failure we do NOT
      // force-return, so the method runs unmodified (fail-safe).
      t_in_hook = true;
      CallbackReturnResult res = RunCallbackReturn(thread, matched, sf, method);
      t_in_hook = false;
      if (!res.ok) {
        return;
      }
      t_pending.push_back({sf, method, matched, res.ref, res.is_void});
      sf->SetForcePopFrame(true);
      return;
    }
    t_pending.push_back({sf, method, matched});
    sf->SetForcePopFrame(true);
  }

  void NonStandardExitPopped(Thread* thread, const ShadowFrame& frame, JValue& return_value)
      override REQUIRES_SHARED(Locks::mutator_lock_) {
    for (auto it = t_pending.begin(); it != t_pending.end(); ++it) {
      if (it->frame == &frame && it->method == frame.GetMethod()) {
        if (it->rule->action == ActionKind::kCallbackReturn) {
          // Value was computed in MethodEntered and carried as a global ref / void marker.
          if (it->cb_void) {
            // void: leave return_value default.
          } else {
            return_value.SetL(it->cb_ref == nullptr ? nullptr : thread->DecodeJObject(it->cb_ref));
          }
          if (it->cb_ref != nullptr) {
            Runtime::Current()->GetJavaVM()->DeleteGlobalRef(thread, it->cb_ref);
          }
        } else {
          BuildValue(thread, it->rule, &return_value);
        }
        t_pending.erase(it);
        return;
      }
    }
  }

  // Object-returning method exit: apply kCallbackMutateReturn rules, which mutate the returned
  // object in place (e.g. clear ApplicationInfo.FLAG_DEBUGGABLE). A no-op unless a mutate-return rule
  // targets this method. Never force-returns; the real return value is kept, only mutated.
  void MethodExited(Thread* thread, ArtMethod* method, instrumentation::OptionalFrame,
                    MutableHandle<mirror::Object>& return_value) override
      REQUIRES_SHARED(Locks::mutator_lock_) {
    if (t_in_hook || return_value == nullptr) {
      return;
    }
    const Rule* matched = nullptr;
    {
      std::lock_guard<std::mutex> guard(g_lock);
      auto it = g_method_rules.find(method);
      if (it == g_method_rules.end()) {
        return;
      }
      for (const Rule* rule : it->second) {
        if (rule->action == ActionKind::kCallbackMutateReturn && CategoryEnabled(rule->category)) {
          matched = rule;
          break;
        }
      }
    }
    if (matched == nullptr) {
      return;
    }
    t_in_hook = true;
    RunMutateReturnCallback(thread, matched, return_value.Get());
    t_in_hook = false;
  }
  void MethodExited(Thread*, ArtMethod*, instrumentation::OptionalFrame, JValue&) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void MethodUnwind(Thread*, ArtMethod*, uint32_t) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void DexPcMoved(Thread*, Handle<mirror::Object>, ArtMethod*, uint32_t) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void FieldRead(Thread*, Handle<mirror::Object>, ArtMethod*, uint32_t, ArtField*) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void FieldWritten(Thread*, Handle<mirror::Object>, ArtMethod*, uint32_t, ArtField*,
                    const JValue&) override REQUIRES_SHARED(Locks::mutator_lock_) {}
  void ExceptionThrown(Thread*, Handle<mirror::Throwable>) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void ExceptionHandled(Thread*, Handle<mirror::Throwable>) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void Branch(Thread*, ArtMethod*, uint32_t, int32_t) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}
  void WatchedFramePop(Thread*, const ShadowFrame&) override
      REQUIRES_SHARED(Locks::mutator_lock_) {}

 private:
  void BuildValue(Thread* self, const Rule* rule, JValue* out)
      REQUIRES_SHARED(Locks::mutator_lock_) {
    switch (rule->action) {
      case ActionKind::kConstBool:
        out->SetZ(rule->bool_value ? 1 : 0);
        break;
      case ActionKind::kConstInt:
        out->SetI(rule->int_value);
        break;
      case ActionKind::kConstNull:
        out->SetL(nullptr);
        break;
      case ActionKind::kConstVoid:
        // Void return: leave `out` as the default JValue; the body is still skipped.
        break;
      case ActionKind::kConstString: {
        jobject g = InternedFor(rule->string_value);
        out->SetL(g == nullptr ? nullptr : self->DecodeJObject(g));
        break;
      }
      case ActionKind::kConstEmptyList:
        out->SetL(g_empty_list == nullptr ? nullptr : self->DecodeJObject(g_empty_list));
        break;
      case ActionKind::kFieldSetBool:
      case ActionKind::kFieldSetString:
      case ActionKind::kCallbackMutate:
      case ActionKind::kCallbackMutateReturn:
        // Applied at class-prepare / MethodEntered / MethodExited; never a const force-return.
        LOG(FATAL) << "scanner: non-return action reached method return path";
        UNREACHABLE();
      case ActionKind::kCallbackReturn:
        // Delivered directly in NonStandardExitPopped from the precomputed global ref; the value is
        // never rebuilt here.
        LOG(FATAL) << "scanner: kCallbackReturn reached BuildValue";
        UNREACHABLE();
    }
  }
};

ScannerListener* GetListener() {
  static ScannerListener* listener = new ScannerListener();
  return listener;
}

// ---------------------------------------------------------------------------
// Class-load callback
// ---------------------------------------------------------------------------

void ApplyFieldRule(Thread* self, Handle<mirror::Class> klass, const Rule* rule)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  for (ArtField& field : klass->GetFields()) {
    if (!field.IsStatic()) {
      continue;
    }
    if (std::strcmp(field.GetName(), rule->member_name) != 0) {
      continue;
    }
    if (rule->action == ActionKind::kFieldSetBool) {
      field.SetBoolean<false>(klass.Get(), rule->bool_value ? 1 : 0);
    } else {  // kFieldSetString
      ObjPtr<mirror::String> str =
          mirror::String::AllocFromModifiedUtf8(self, rule->string_value);
      if (str != nullptr) {
        field.SetObject<false>(klass.Get(), str);
      }
    }
    return;
  }
}

// True if `desc` names the class itself, any superclass, or any implemented interface of `klass`.
bool DescriptorInHierarchy(ObjPtr<mirror::Class> klass, const char* desc)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  for (ObjPtr<mirror::Class> c = klass; c != nullptr; c = c->GetSuperClass()) {
    if (c->DescriptorEquals(desc)) {
      return true;
    }
  }
  const int32_t count = klass->GetIfTableCount();
  ObjPtr<mirror::IfTable> itable = klass->GetIfTable();
  for (int32_t i = 0; i < count; ++i) {
    ObjPtr<mirror::Class> iface = itable->GetInterface(i);
    if (iface != nullptr && iface->DescriptorEquals(desc)) {
      return true;
    }
  }
  return false;
}

bool ClassMatchesRule(ObjPtr<mirror::Class> klass, const char* descriptor, const Rule* rule)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  return rule->match_subtypes ? DescriptorInHierarchy(klass, rule->class_descriptor)
                              : (std::strcmp(descriptor, rule->class_descriptor) == 0);
}

// Deoptimizes a single method so it runs in the interpreter (where method-entry events fire and the
// force-pop return substitution works). Same shape as the JVMTI limited-deopt path: enter a
// suspended state, then a GC-critical section + suspend-all to get the exclusive mutator lock that
// Instrumentation::Deoptimize requires. Call only when NOT already under a suspend-all.
void DeoptimizeMethodStandalone(ArtMethod* method) REQUIRES_SHARED(Locks::mutator_lock_) {
  Thread* self = Thread::Current();
  ScopedThreadSuspension sts(self, ThreadState::kSuspended);
  gc::ScopedGCCriticalSection gcs(self, gc::kGcCauseInstrumentation,
                                  gc::kCollectorTypeInstrumentation);
  ScopedSuspendAll ssa("scanner method deopt");
  instrumentation::Instrumentation* instr = Runtime::Current()->GetInstrumentation();
  if (!instr->IsDeoptimized(method)) {  // guard: Deoptimize aborts if already deoptimized
    instr->Deoptimize(method);
  }
}

void ApplyMethodRule(Handle<mirror::Class> klass, const Rule* rule)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  for (ArtMethod& method : klass->GetMethods(kRuntimePointerSize)) {
    if (!method.IsInvokable() || method.IsAbstract() || method.IsNative() ||
        method.IsProxyMethod()) {
      continue;  // can't deoptimize / no interpreter frame to force-pop
    }
    if (std::strcmp(method.GetName(), rule->member_name) != 0) {
      continue;
    }
    if (rule->return_shorty != 0) {
      const char* shorty = method.GetShorty();
      if (shorty == nullptr || shorty[0] != rule->return_shorty) {
        continue;
      }
    }
    // Record the method->rule mapping (used by MethodEntered) and whether this is the first rule on
    // the method (so it needs deoptimizing exactly once).
    bool needs_deopt;
    {
      std::lock_guard<std::mutex> guard(g_lock);
      auto& rules = g_method_rules[&method];
      needs_deopt = rules.empty();
      rules.push_back(rule);
    }
    if (!needs_deopt) {
      continue;
    }
    // Deoptimize only this method (JVMTI-style), not the whole process. During the install sweep we
    // are about to take the install suspend-all, so just queue it; afterwards (ClassPrepare for a
    // newly-loaded class) deoptimize it inline.
    if (g_installing.load()) {
      std::lock_guard<std::mutex> guard(g_lock);
      g_pending_deopt.push_back(&method);
    } else {
      DeoptimizeMethodStandalone(&method);
    }
  }
}

// Applies all matching rules to one class: spoofs fields and records method->rule mappings. Shared
// by ClassPrepare (classes loaded after install) and the install-time sweep (classes already
// loaded, e.g. the zygote-preloaded framework classes android.os.Build / java.io.File / ... which
// never get a ClassPrepare callback). Handle-izes the class so field-string allocation is safe.
void ProcessClass(Thread* self, ObjPtr<mirror::Class> klass_ptr)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  StackHandleScope<1> hs(self);
  Handle<mirror::Class> klass = hs.NewHandle(klass_ptr);
  std::string storage;
  const char* descriptor = klass->GetDescriptor(&storage);
  for (const Rule& rule : kRules) {
    if (!CategoryEnabled(rule.category)) {
      continue;  // category toggled off via properties
    }
    if (!ClassMatchesRule(klass.Get(), descriptor, &rule)) {
      continue;
    }
    if (rule.is_field) {
      ApplyFieldRule(self, klass, &rule);
    } else {
      ApplyMethodRule(klass, &rule);
    }
  }
}

class ScannerClassCallback final : public ClassLoadCallback {
 public:
  void ClassLoad(Handle<mirror::Class>) override REQUIRES_SHARED(Locks::mutator_lock_) {}

  void ClassPrepare(Handle<mirror::Class> /*temp_klass*/, Handle<mirror::Class> klass)
      override REQUIRES_SHARED(Locks::mutator_lock_) {
    ProcessClass(Thread::Current(), klass.Get());
  }
};

ScannerClassCallback* GetClassCallback() {
  static ScannerClassCallback* cb = new ScannerClassCallback();
  return cb;
}

// Visitor that applies rules to every already-loaded class during install.
class ScannerSweepVisitor final : public ClassVisitor {
 public:
  explicit ScannerSweepVisitor(Thread* self) : self_(self) {}
  bool operator()(ObjPtr<mirror::Class> klass) override REQUIRES_SHARED(Locks::mutator_lock_) {
    ProcessClass(self_, klass);
    return true;  // visit all
  }

 private:
  Thread* const self_;
};

// Sweeps classes already loaded before the hooks were installed. ClassPrepare only fires for
// classes loaded afterwards, but the targeted framework classes are mostly preloaded in the zygote,
// so without this sweep their field spoofs and method rules would never be applied.
// Uses the lock-free variant so the field-string allocations in ProcessClass are safe (the
// classlinker classes lock is not held across the visit).
void SweepLoadedClasses(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  ScannerSweepVisitor visitor(self);
  Runtime::Current()->GetClassLinker()->VisitClassesWithoutClassesLock(&visitor);
}

// Resolves java.util.Collections.EMPTY_LIST into a JNI global ref, if any rule needs it.
void ResolveEmptyList(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  bool needed = false;
  for (const Rule& rule : kRules) {
    if (rule.action == ActionKind::kConstEmptyList) {
      needed = true;
      break;
    }
  }
  if (!needed) {
    return;
  }
  ObjPtr<mirror::Class> klass =
      Runtime::Current()->GetClassLinker()->FindSystemClass(self, kCollectionsDescriptor);
  if (klass == nullptr) {
    self->ClearException();
    return;
  }
  ArtField* field = klass->FindDeclaredStaticField(kEmptyListFieldName, kListDescriptor);
  if (field == nullptr) {
    return;
  }
  ObjPtr<mirror::Object> value = field->GetObject(klass);
  if (value != nullptr) {
    g_empty_list = Runtime::Current()->GetJavaVM()->AddGlobalRef(self, value);
  }
}

// Resolves android.os.Debug.waitForDebugger() once so the debugger-detection gate can recognise
// its calls by pointer. If this fails the exemption is lost, so a process started in
// wait-for-debugger mode would hang (its poll of isDebuggerConnected gets the spoofed value).
void ResolveWaitForDebugger(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  ObjPtr<mirror::Class> klass =
      Runtime::Current()->GetClassLinker()->FindSystemClass(self, kDebugDescriptor);
  if (klass == nullptr) {
    self->ClearException();
    return;
  }
  g_wait_for_debugger =
      klass->FindClassMethod(kWaitForDebuggerName, kVoidNoArgsSignature, kRuntimePointerSize);
}

// Interns String return constants as JNI global refs. Uses JavaVMExt::AddGlobalRef (which takes an
// ObjPtr directly) so it needs only a Runnable thread, not a ScopedObjectAccess - it is called from
// DoInstall, which already runs on a Runnable thread.
void InternStrings(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  std::lock_guard<std::mutex> guard(g_lock);
  for (const Rule& rule : kRules) {
    if (rule.action != ActionKind::kConstString || rule.string_value == nullptr) {
      continue;
    }
    if (g_interned.find(rule.string_value) != g_interned.end()) {
      continue;
    }
    ObjPtr<mirror::String> str = mirror::String::AllocFromModifiedUtf8(self, rule.string_value);
    if (str == nullptr) {
      continue;
    }
    g_interned[rule.string_value] = Runtime::Current()->GetJavaVM()->AddGlobalRef(self, str);
  }
}

// Performs the actual install in the target process. Called from Install(), OnProcessPackageName()
// or the AppInfoCallback, each on a Runnable thread (REQUIRES_SHARED). Installs once.
void DoInstall() REQUIRES_SHARED(Locks::mutator_lock_) {
  bool expected = false;
  if (!g_installed.compare_exchange_strong(expected, true)) {
    return;
  }
  Runtime* runtime = Runtime::Current();
  Thread* self = Thread::Current();

  // Forcing an early return from an entry hook requires non-standard exits to be enabled
  // process-wide; the interpreter DCHECKs Runtime::AreNonStandardExitsEnabled() on that path.
  runtime->SetNonStandardExitsEnabled();

  // Intern String constants / resolve EMPTY_LIST (needs a Runnable thread to allocate - we have it).
  InternStrings(self);
  ResolveEmptyList(self);
  ResolveWaitForDebugger(self);

  // Sweep already-loaded classes (zygote-preloaded framework classes never get a ClassPrepare
  // callback): sets spoofed fields and records method->rule mappings, queuing the matched methods
  // into g_pending_deopt (g_installing == true) rather than deoptimizing each inline.
  g_installing.store(true);
  SweepLoadedClasses(self);
  g_installing.store(false);

  // Register the class-load callback + the instrumentation listener, and deoptimize exactly the
  // matched methods (JVMTI-style per-method deopt - NOT the whole process). All require the
  // exclusive mutator lock, so run them under one suspend-all; drop to kSuspended first since we
  // enter here Runnable.
  size_t deopted = 0;
  {
    ScopedThreadSuspension sts(self, ThreadState::kSuspended);
    gc::ScopedGCCriticalSection gcs(self, gc::kGcCauseInstrumentation,
                                    gc::kCollectorTypeInstrumentation);
    ScopedSuspendAll ssa("scanner hooks install");
    runtime->GetRuntimeCallbacks()->AddClassLoadCallback(GetClassCallback());
    instrumentation::Instrumentation* instr = runtime->GetInstrumentation();
    instr->AddListener(GetListener(),
                       instrumentation::Instrumentation::kMethodEntered |
                           instrumentation::Instrumentation::kMethodExited);
    std::lock_guard<std::mutex> guard(g_lock);
    for (ArtMethod* m : g_pending_deopt) {
      if (!instr->IsDeoptimized(m)) {  // guard: Deoptimize aborts if already deoptimized
        instr->Deoptimize(m);
      }
    }
    deopted = g_pending_deopt.size();
    g_pending_deopt.clear();
  }

  LOG(INFO) << "scanner: hooks installed for process " << g_target_package << " ("
            << deopted << " methods deoptimized"
            << ", wait_for_debugger_resolved=" << (g_wait_for_debugger != nullptr)
            << ", empty_list_resolved=" << (g_empty_list != nullptr) << ")";
}

// Installs the hooks if `candidate` (a process name or package name) matches the configured target,
// or if this process's already-registered package name matches. Robust to which of the AppInfo
// callbacks actually fires in a given launch flow.
void MaybeInstall(const char* source, const std::string& candidate)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  const std::string& pkg = Runtime::Current()->GetProcessPackageName();
  LOG(INFO) << "scanner: AppInfo." << source << "='" << candidate << "' processPackage='" << pkg
            << "' target='" << g_target_package << "'";
  if (g_target_package.empty()) {
    return;
  }
  if (candidate == g_target_package || pkg == g_target_package) {
    DoInstall();
  }
}

// Fires when the app registers its process info, which is where the process package becomes known.
// Only the configured target package installs the hooks; every other app process does nothing.
class ScannerAppInfoCallback final : public AppInfoCallback {
 public:
  void SetCurrentProcessName(const std::string& process_name)
      override REQUIRES_SHARED(Locks::mutator_lock_) {
    MaybeInstall("SetCurrentProcessName", process_name);
  }
  void AddApplication(const std::string& package_name)
      override REQUIRES_SHARED(Locks::mutator_lock_) {
    MaybeInstall("AddApplication", package_name);
  }
  void RemoveApplication(const std::string&) override REQUIRES_SHARED(Locks::mutator_lock_) {}
  void SetWaitingForDebugger(bool) override REQUIRES_SHARED(Locks::mutator_lock_) {}
  void SetUserId(int) override REQUIRES_SHARED(Locks::mutator_lock_) {}
};

AppInfoCallback* GetAppInfoCallback() {
  static ScannerAppInfoCallback* cb = new ScannerAppInfoCallback();
  return cb;
}

// Reads this process's name at post-fork time. /proc/self/cmdline may still read "zygote" this
// early, so it is used only when it already holds the app name; otherwise fall back to the thread
// name (prctl, 15-char-truncated), which the zygote sets to the process name before these hooks run.
std::string ReadProcName() {
  std::string cmdline;
  if (android::base::ReadFileToString("/proc/self/cmdline", &cmdline)) {
    size_t nul = cmdline.find('\0');
    if (nul != std::string::npos) {
      cmdline.resize(nul);
    }
    if (!cmdline.empty() && cmdline != kZygoteProcName && cmdline != kZygote64ProcName) {
      return cmdline;
    }
  }
  char comm[32] = {0};
  if (prctl(PR_GET_NAME, comm, 0, 0, 0) == 0 && comm[0] != '\0') {
    return std::string(comm);
  }
  return "";
}

// Matches the process name against the target package, tolerating the 15-char thread-name
// truncation (then target must start with the truncated name).
bool NameMatchesTarget(const std::string& name) {
  if (name.empty() || g_target_package.empty()) {
    return false;
  }
  if (name == g_target_package) {
    return true;
  }
  return name.size() >= 15 && g_target_package.rfind(name, 0) == 0;
}

}  // namespace

void ScannerHooks::Install() {
  // Configuration comes from system properties, read once here at process start. If no target
  // package is configured, or no rule category is enabled, do nothing (skip all install work).
  g_target_package = android::base::GetProperty(kPropTarget, "");
  g_cat_rasp = android::base::GetBoolProperty(kPropRasp, false);
  g_cat_ssl = android::base::GetBoolProperty(kPropSsl, false);
  g_cat_pkg = android::base::GetBoolProperty(kPropPackage, false);
  g_cat_secure = android::base::GetBoolProperty(kPropSecureFlag, false);
  g_cat_debugger = android::base::GetBoolProperty(kPropDebugger, false);
  g_verbose = android::base::GetBoolProperty(kPropVerbose, false);
  // Device API level, used by the Google-package spoof rules to pick version-specific object shapes.
  g_sdk_int = android::base::GetIntProperty("ro.build.version.sdk", 0);
  if (g_target_package.empty() || !AnyCategoryEnabled()) {
    return;
  }

  // When the target app is launched waiting for a debugger, the normal AppInfoCallback path can be
  // suppressed. So gate on the process name available right here at post-fork (from
  // /proc/self/cmdline), and install immediately if this is the target. Keep the AppInfoCallback only
  // as a fallback for launch flows where the name isn't set this early.
  Thread* self = Thread::Current();
  std::string proc_name = ReadProcName();
  bool is_target = NameMatchesTarget(proc_name);
  LOG(INFO) << "scanner: Install procName='" << proc_name << "' target='" << g_target_package
            << "' match=" << is_target << " (rasp=" << g_cat_rasp << " ssl=" << g_cat_ssl
            << " pkg=" << g_cat_pkg << " secure=" << g_cat_secure
            << " debugger=" << g_cat_debugger << ")";

  ScopedObjectAccess soa(self);
  if (is_target) {
    DoInstall();
  } else {
    Runtime::Current()->GetRuntimeCallbacks()->AddAppInfoCallback(GetAppInfoCallback());
  }
}

void ScannerHooks::OnProcessPackageName(const char* package_name) {
  // The reliable install gate: called from VMRuntime.setProcessPackageName with the full,
  // untruncated package name, which only becomes known during bindApplication (long after the
  // post-fork Install(), where /proc/self/cmdline is still "zygote" and comm is capped at 15 chars).
  if (package_name == nullptr || g_target_package.empty() || !AnyCategoryEnabled()) {
    return;
  }
  if (g_installed.load()) {
    return;
  }
  if (g_target_package != package_name) {
    return;  // not our target process
  }
  Thread* self = Thread::Current();
  LOG(INFO) << "scanner: OnProcessPackageName matched target '" << package_name << "'; installing";
  ScopedObjectAccess soa(self);  // JNI native context is kNative; DoInstall needs Runnable
  DoInstall();
}

}  // namespace art
