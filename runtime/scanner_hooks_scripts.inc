/*
 * scanner_hooks rule action scripts.
 *
 * Imperative rule actions that read and/or mutate frame state, invoke managed framework code, build
 * framework objects, or compute a return value — anything beyond a constant force-return (which the
 * table and BuildValue handle directly). Kept next to the rule data and apart from the
 * general-purpose frame inspection/modification helpers in scanner_hooks.cc, which these call.
 *
 * Textually included by scanner_hooks.cc from inside its anonymous namespace, AFTER those frame
 * helpers are defined (this file calls GetArgObject / GetStringFieldOf / SetStringField / GetArgSlot)
 * and BEFORE the instrumentation listener that dispatches to these functions. Not a standalone
 * translation unit; no include guards; do not #include it anywhere else.
 *
 * FAIL-SAFE INVARIANT: every managed invoke / object build here must degrade to "rule did not fire"
 * on any missing class / field / method, null arg, unexpected object shape, or pending exception —
 * never a crash. Each helper null-checks and clears pending exceptions; callbacks that cannot
 * complete return failure so the hooked method simply runs unmodified.
 */

// ---------------------------------------------------------------------------
// Framework class descriptors / member names used by the signature-spoof + SSL callbacks
// ---------------------------------------------------------------------------
constexpr const char* kArraysDescriptor = "Ljava/util/Arrays;";
constexpr const char* kAsListName = "asList";
constexpr const char* kAsListSig = "([Ljava/lang/Object;)Ljava/util/List;";
constexpr const char* kProceedName = "proceed";  // android.webkit.SslErrorHandler.proceed()V

constexpr const char* kSignatureDescriptor = "Landroid/content/pm/Signature;";
constexpr const char* kSignatureArrayDescriptor = "[Landroid/content/pm/Signature;";
constexpr const char* kSignatureBytesField = "mSignature";  // byte[]
constexpr const char* kByteArrayDescriptor = "[B";

constexpr const char* kSigningInfoDescriptor = "Landroid/content/pm/SigningInfo;";
constexpr const char* kSigningDetailsField = "mSigningDetails";
// android.content.pm.SigningDetails moved from PackageParser.SigningDetails (pre-T) to a top-level
// class in API 33 (T). Pick per g_sdk_int.
constexpr const char* kSigningDetailsDescriptorT = "Landroid/content/pm/SigningDetails;";
constexpr const char* kSigningDetailsDescriptorLegacy =
    "Landroid/content/pm/PackageParser$SigningDetails;";
constexpr const char* kSigningDetailsCtorSig = "([Landroid/content/pm/Signature;I)V";
constexpr int32_t kSignatureSchemeVersion = 3;  // SigningDetails signature-scheme-version argument

constexpr const char* kPackageInfoDescriptor = "Landroid/content/pm/PackageInfo;";
constexpr const char* kApplicationInfoDescriptor = "Landroid/content/pm/ApplicationInfo;";
constexpr const char* kPkgSignaturesField = "signatures";          // Signature[]
constexpr const char* kPkgSigningInfoField = "signingInfo";        // SigningInfo
constexpr const char* kPkgPackageNameField = "packageName";        // String
constexpr const char* kPkgApplicationInfoField = "applicationInfo";  // ApplicationInfo
constexpr const char* kAppInfoFlagsField = "flags";                // int
constexpr const char* kAppInfoEnabledField = "enabled";            // boolean
constexpr const char* kCtorName = "<init>";

constexpr const char* kFakeGooglePackageName = "com.android.vending";
constexpr int32_t kFakeGoogleAppInfoFlags = 129;  // FLAG_SYSTEM | FLAG_UPDATED_SYSTEM_APP

constexpr int32_t kFlagDebuggable = 0x2;  // ApplicationInfo.FLAG_DEBUGGABLE

// ---------------------------------------------------------------------------
// Managed-invoke + object-building primitives (fail-safe)
// ---------------------------------------------------------------------------

// Marshals a reference into the uint32_t arg slot layout ArtMethod::Invoke expects (same encoding as
// reflection.cc's ArgArray::Append).
uint32_t RefSlot(ObjPtr<mirror::Object> o) REQUIRES_SHARED(Locks::mutator_lock_) {
  return StackReference<mirror::Object>::FromMirrorPtr(o.Ptr()).AsVRegValue();
}

// Resolves a bootclasspath class by descriptor; clears any pending exception and returns null on
// failure (e.g. the class does not exist on this API level).
ObjPtr<mirror::Class> ResolveSystemClass(Thread* self, const char* descriptor)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  ObjPtr<mirror::Class> klass =
      Runtime::Current()->GetClassLinker()->FindSystemClass(self, descriptor);
  if (klass == nullptr) {
    self->ClearException();
  }
  return klass;
}

// Thin, fail-safe wrapper over ArtMethod::Invoke. Caller pre-marshals args (refs via RefSlot).
// Returns false (clearing any exception) on a null method or a thrown exception, so the caller can
// no-op. Must be called with t_in_hook already true (so the invoked managed code does not re-enter
// our listener).
bool InvokeManaged(Thread* self, ArtMethod* m, uint32_t* args, uint32_t args_size,
                   const char* shorty, JValue* result) REQUIRES_SHARED(Locks::mutator_lock_) {
  if (m == nullptr) {
    return false;
  }
  m->Invoke(self, args, args_size, result, shorty);
  if (self->IsExceptionPending()) {
    self->ClearException();
    return false;
  }
  return true;
}

// Builds a managed byte[] from raw bytes, or null on allocation failure.
ObjPtr<mirror::ByteArray> BuildByteArray(Thread* self, const uint8_t* data, size_t len)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  ObjPtr<mirror::ByteArray> arr = mirror::ByteArray::Alloc(self, static_cast<int32_t>(len));
  if (arr == nullptr) {
    self->ClearException();
    return nullptr;
  }
  if (len > 0) {
    memcpy(arr->GetData(), data, len);
  }
  return arr;
}

// Builds one android.content.pm.Signature from DER bytes. Allocates the object and sets its
// mSignature field directly (the Signature(byte[]) ctor does only that), avoiding a managed invoke.
// Returns null on any missing field / allocation failure. `sig_class` must be the Signature class.
ObjPtr<mirror::Object> BuildSignature(Thread* self, Handle<mirror::Class> sig_class,
                                      const uint8_t* der, size_t len)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  StackHandleScope<2> hs(self);
  Handle<mirror::ByteArray> bytes(hs.NewHandle(BuildByteArray(self, der, len)));
  if (bytes == nullptr) {
    return nullptr;
  }
  Handle<mirror::Object> sig(hs.NewHandle(sig_class->AllocObject(self)));
  if (sig == nullptr) {
    self->ClearException();
    return nullptr;
  }
  ArtField* f = sig_class->FindDeclaredInstanceField(kSignatureBytesField, kByteArrayDescriptor);
  if (f == nullptr) {
    return nullptr;
  }
  f->SetObject<false>(sig.Get(), bytes.Get());
  return sig.Get();
}

// Builds a Signature[] from a list of DER certs, or null on any failure.
ObjPtr<mirror::ObjectArray<mirror::Object>> BuildSignatureArray(
    Thread* self, const std::vector<std::vector<uint8_t>>& certs)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  StackHandleScope<3> hs(self);
  Handle<mirror::Class> sig_class(hs.NewHandle(ResolveSystemClass(self, kSignatureDescriptor)));
  if (sig_class == nullptr) {
    return nullptr;
  }
  Handle<mirror::Class> arr_class(hs.NewHandle(ResolveSystemClass(self, kSignatureArrayDescriptor)));
  if (arr_class == nullptr) {
    return nullptr;
  }
  Handle<mirror::ObjectArray<mirror::Object>> arr(hs.NewHandle(
      mirror::ObjectArray<mirror::Object>::Alloc(self, arr_class.Get(),
                                                 static_cast<int32_t>(certs.size()))));
  if (arr == nullptr) {
    self->ClearException();
    return nullptr;
  }
  for (size_t i = 0; i < certs.size(); ++i) {
    ObjPtr<mirror::Object> sig = BuildSignature(self, sig_class, certs[i].data(), certs[i].size());
    if (sig == nullptr) {
      return nullptr;
    }
    arr->Set(static_cast<int32_t>(i), sig);  // stored immediately; no alloc between build and Set
  }
  return arr.Get();
}

// Builds an android.content.pm.SigningInfo wrapping a SigningDetails built from `sigs`. Returns null
// on any missing class/field/ctor (so the caller keeps the plain-signatures spoof). `sigs` is a
// Signature[].
ObjPtr<mirror::Object> BuildSigningInfo(Thread* self,
                                        Handle<mirror::ObjectArray<mirror::Object>> sigs)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  StackHandleScope<4> hs(self);
  const char* details_desc =
      (g_sdk_int >= 33) ? kSigningDetailsDescriptorT : kSigningDetailsDescriptorLegacy;
  Handle<mirror::Class> details_class(hs.NewHandle(ResolveSystemClass(self, details_desc)));
  if (details_class == nullptr) {
    return nullptr;
  }
  ArtMethod* ctor =
      details_class->FindClassMethod(kCtorName, kSigningDetailsCtorSig, kRuntimePointerSize);
  if (ctor == nullptr) {
    return nullptr;
  }
  Handle<mirror::Object> details(hs.NewHandle(details_class->AllocObject(self)));
  if (details == nullptr) {
    self->ClearException();
    return nullptr;
  }
  // new SigningDetails(Signature[], int schemeVersion): args = [receiver, sigs, 3], shorty "VLI".
  uint32_t args[3] = {RefSlot(details.Get()), RefSlot(sigs.Get()),
                      static_cast<uint32_t>(kSignatureSchemeVersion)};
  JValue result;
  if (!InvokeManaged(self, ctor, args, sizeof(args), "VLI", &result)) {
    return nullptr;
  }
  Handle<mirror::Class> si_class(hs.NewHandle(ResolveSystemClass(self, kSigningInfoDescriptor)));
  if (si_class == nullptr) {
    return nullptr;
  }
  Handle<mirror::Object> si(hs.NewHandle(si_class->AllocObject(self)));
  if (si == nullptr) {
    self->ClearException();
    return nullptr;
  }
  ArtField* f = si_class->FindDeclaredInstanceField(kSigningDetailsField, details_desc);
  if (f == nullptr) {
    return nullptr;
  }
  f->SetObject<false>(si.Get(), details.Get());
  return si.Get();
}

// Builds an android.content.pm.PackageInfo carrying `sigs` as its signatures (and, if
// with_signing_info, a SigningInfo). When package_name is non-null it is set. When google_app_info is
// true an ApplicationInfo (flags=129, enabled=true) is attached (fake Google package). Returns null
// on failure. `sigs` is a Signature[].
ObjPtr<mirror::Object> BuildPackageInfo(Thread* self, const char* package_name,
                                        Handle<mirror::ObjectArray<mirror::Object>> sigs,
                                        bool with_signing_info, bool google_app_info)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  StackHandleScope<4> hs(self);
  Handle<mirror::Class> pi_class(hs.NewHandle(ResolveSystemClass(self, kPackageInfoDescriptor)));
  if (pi_class == nullptr) {
    return nullptr;
  }
  Handle<mirror::Object> pi(hs.NewHandle(pi_class->AllocObject(self)));
  if (pi == nullptr) {
    self->ClearException();
    return nullptr;
  }
  // signatures (always)
  ArtField* f_sigs =
      pi_class->FindDeclaredInstanceField(kPkgSignaturesField, kSignatureArrayDescriptor);
  if (f_sigs == nullptr) {
    return nullptr;  // without the signatures field this rule is pointless
  }
  f_sigs->SetObject<false>(pi.Get(), sigs.Get());
  // packageName (optional; allocate last-minute, store immediately)
  if (package_name != nullptr) {
    ObjPtr<mirror::String> name = mirror::String::AllocFromModifiedUtf8(self, package_name);
    if (name != nullptr) {
      SetStringField(pi.Get(), kPkgPackageNameField, name);
    } else {
      self->ClearException();
    }
  }
  // signingInfo (optional, best-effort: failure leaves just signatures set)
  if (with_signing_info) {
    ObjPtr<mirror::Object> si = BuildSigningInfo(self, sigs);
    if (si != nullptr) {
      ArtField* f_si =
          pi_class->FindDeclaredInstanceField(kPkgSigningInfoField, kSigningInfoDescriptor);
      if (f_si != nullptr) {
        f_si->SetObject<false>(pi.Get(), si);
      }
    }
  }
  // applicationInfo for the fake Google package (best-effort)
  if (google_app_info) {
    Handle<mirror::Class> ai_class(hs.NewHandle(ResolveSystemClass(self, kApplicationInfoDescriptor)));
    if (ai_class != nullptr) {
      ObjPtr<mirror::Object> ai = ai_class->AllocObject(self);
      if (ai != nullptr) {
        ArtField* f_flags = ai_class->FindDeclaredInstanceField(kAppInfoFlagsField, "I");
        if (f_flags != nullptr) {
          f_flags->SetInt<false>(ai, kFakeGoogleAppInfoFlags);
        }
        ArtField* f_enabled = ai_class->FindDeclaredInstanceField(kAppInfoEnabledField, "Z");
        if (f_enabled != nullptr) {
          f_enabled->SetBoolean<false>(ai, 1);
        }
        ArtField* f_ai =
            pi_class->FindDeclaredInstanceField(kPkgApplicationInfoField, kApplicationInfoDescriptor);
        if (f_ai != nullptr) {
          f_ai->SetObject<false>(pi.Get(), ai);
        }
      } else {
        self->ClearException();
      }
    }
  }
  return pi.Get();
}

// ---------------------------------------------------------------------------
// kCallbackReturn: compute a return value (may invoke managed code)
// ---------------------------------------------------------------------------

// Result of a compute-and-return callback. ref is a JNI global ref to the object result (released by
// the listener after delivery); is_void marks a void force-return; ok=false means "do not
// force-return" (method runs unmodified).
struct CallbackReturnResult {
  bool ok = false;
  bool is_void = false;
  jobject ref = nullptr;
};

CallbackReturnResult MakeObjectResult(Thread* self, ObjPtr<mirror::Object> obj)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  CallbackReturnResult r;
  r.ok = true;
  r.is_void = false;
  r.ref = (obj == nullptr) ? nullptr : Runtime::Current()->GetJavaVM()->AddGlobalRef(self, obj);
  return r;
}

CallbackReturnResult RunCallbackReturn(Thread* self, const Rule* rule, ShadowFrame* sf,
                                       ArtMethod* method) REQUIRES_SHARED(Locks::mutator_lock_) {
  CallbackReturnResult fail;  // ok == false
  switch (rule->int_value) {
    case kCbCheckServerTrustedList: {
      // X509TrustManager.checkServerTrusted(X509Certificate[] chain, ...): return Arrays.asList(chain).
      mirror::Object* chain = GetArgObject(sf, method, 0);
      if (chain == nullptr) {
        return fail;
      }
      StackHandleScope<2> hs(self);
      Handle<mirror::Object> chain_h(hs.NewHandle(chain));
      Handle<mirror::Class> arrays(hs.NewHandle(ResolveSystemClass(self, kArraysDescriptor)));
      if (arrays == nullptr) {
        return fail;
      }
      ArtMethod* as_list = arrays->FindClassMethod(kAsListName, kAsListSig, kRuntimePointerSize);
      uint32_t args[1] = {RefSlot(chain_h.Get())};
      JValue result;
      if (!InvokeManaged(self, as_list, args, sizeof(args), "LL", &result)) {
        return fail;
      }
      return MakeObjectResult(self, result.GetL());
    }
    case kCbWebViewProceed: {
      // WebViewClient.onReceivedSslError(WebView, SslErrorHandler handler, SslError): handler.proceed().
      mirror::Object* handler = GetArgObject(sf, method, 1);
      if (handler == nullptr) {
        return fail;
      }
      StackHandleScope<1> hs(self);
      Handle<mirror::Object> handler_h(hs.NewHandle(handler));
      ArtMethod* proceed =
          handler_h->GetClass()->FindClassMethod(kProceedName, kVoidNoArgsSignature,
                                                  kRuntimePointerSize);
      uint32_t args[1] = {RefSlot(handler_h.Get())};
      JValue result;
      if (!InvokeManaged(self, proceed, args, sizeof(args), "V", &result)) {
        return fail;
      }
      CallbackReturnResult r;
      r.ok = true;
      r.is_void = true;  // onReceivedSslError returns void
      return r;
    }
    case kCbFakeGooglePackageInfo: {
      // getPackageInfo("com.android.vending"/gms, ...): return a fabricated Google PackageInfo built
      // off the embedded Google platform signing cert.
      std::vector<std::vector<uint8_t>> certs;
      certs.emplace_back(kGoogleCertDer, kGoogleCertDer + kGoogleCertDerLen);
      StackHandleScope<1> hs(self);
      Handle<mirror::ObjectArray<mirror::Object>> sigs(hs.NewHandle(BuildSignatureArray(self, certs)));
      if (sigs == nullptr) {
        return fail;
      }
      ObjPtr<mirror::Object> pkg = BuildPackageInfo(self, kFakeGooglePackageName, sigs,
                                                    /*with_signing_info=*/true,
                                                    /*google_app_info=*/true);
      if (pkg == nullptr) {
        return fail;
      }
      return MakeObjectResult(self, pkg);
    }
    default:
      return fail;
  }
}

// ---------------------------------------------------------------------------
// kCallbackMutateReturn: mutate the returned object on MethodExited
// ---------------------------------------------------------------------------

void RunMutateReturnCallback(Thread* self, const Rule* rule, ObjPtr<mirror::Object> ret)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  if (ret == nullptr) {
    return;
  }
  switch (rule->int_value) {
    case kCbClearApplicationInfoDebuggable: {
      // ApplicationInfo returned by getApplicationInfo: clear FLAG_DEBUGGABLE so a later read of
      // appInfo.flags no longer reports the app as debuggable (field reads can't be intercepted, so
      // we clear the bit on the object itself).
      ObjPtr<mirror::Class> ai_class = ret->GetClass();
      ArtField* f = ai_class->FindDeclaredInstanceField(kAppInfoFlagsField, "I");
      if (f != nullptr) {
        f->SetInt<false>(ret, f->GetInt(ret) & ~kFlagDebuggable);
      }
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// kCallbackMutate: mutate arg/this/caller state, then let the method run
// ---------------------------------------------------------------------------

// Forces the void-returning caller of SSLPeerUnverifiedException.<init> to return instead of
// throwing. This covers certificate-pinning checks that construct and throw the exception directly
// (a void-returning check method) rather than failing through one of the hooked verifier methods.
// We are synchronously inside the ctor's entry hook on our own thread; the caller is parked at the
// invoke, a safe point. When the caller already runs interpreted we set force-pop on its shadow
// frame directly — the interpreter honors it before the caller's next instruction (the `throw`), so
// the caller returns void instead. A COMPILED caller cannot be handled here: materializing its
// interpreter frame requires deoptimizing the stack, and Instrumentation::InstrumentThreadStack
// needs the mutator lock held exclusively, which an entry hook (held shared / Runnable) cannot take.
// That case is left unmodified (fail-safe); pinning checks typically run interpreted early on and
// under instrumentation, which is when this fires.
void ForceStepOutVoidCaller(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_) {
  struct CallerVisitor final : public StackVisitor {
    explicit CallerVisitor(Thread* t)
        : StackVisitor(t, nullptr, StackWalkKind::kIncludeInlinedFrames) {}
    bool VisitFrame() override REQUIRES_SHARED(Locks::mutator_lock_) {
      ArtMethod* m = GetMethod();
      if (m == nullptr) {
        return true;  // transition / runtime frame; keep walking
      }
      if (depth_ == 0) {
        depth_ = 1;  // frame 0 is the ctor itself
        return true;
      }
      caller = m;
      caller_returns_void = (m->GetShorty() != nullptr && m->GetShorty()[0] == 'V');
      caller_sf = GetCurrentShadowFrame();  // non-null only for an interpreted caller
      return false;  // stop at the caller
    }
    int depth_ = 0;
    ArtMethod* caller = nullptr;
    bool caller_returns_void = false;
    ShadowFrame* caller_sf = nullptr;
  };

  CallerVisitor v(self);
  v.WalkStack();
  if (v.caller != nullptr && v.caller_returns_void && v.caller_sf != nullptr) {
    v.caller_sf->SetForcePopFrame(true);
  }
}

// Runs a kCallbackMutate rule. Mutates arg/this/caller state in place; the method then runs normally.
void RunMutateCallback(Thread* self, const Rule* rule, ShadowFrame* sf, ArtMethod* method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  switch (rule->int_value) {
    case kCbBindServiceSpoof: {
      // bindService(Intent, ServiceConnection, int): when the Intent's action is a Play Integrity /
      // SafetyNet bind, repoint it from the real GMS/Play package to the decoy helper app
      // (kBindServiceSpoofPackage), which answers with stub/benign results.
      mirror::Object* intent = GetArgObject(sf, method, 0);
      if (intent == nullptr) {
        return;
      }
      ObjPtr<mirror::String> action = GetStringFieldOf(intent, kIntentActionField);
      if (action == nullptr) {
        return;
      }
      bool matched = false;
      for (const char* a : kIntegrityBindActions) {
        if (action->Equals(a)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return;
      }
      ObjPtr<mirror::String> fake =
          mirror::String::AllocFromModifiedUtf8(self, kBindServiceSpoofPackage);
      if (fake != nullptr) {
        SetStringField(intent, kIntentPackageField, fake);
      }
      break;
    }
    case kCbClearSecureFlag: {
      // Window.addFlags(int) / setFlags(int flags, int mask): clear FLAG_SECURE from the int args in
      // place so the secure flag can never be applied. addFlags has one int (arg 0); setFlags has two
      // (args 0 and 1). GetArgSlot returns -1 for an absent arg, so the second clear is a no-op for
      // addFlags.
      static constexpr int32_t kFlagSecure = 0x2000;  // WindowManager.LayoutParams.FLAG_SECURE
      int slot0 = GetArgSlot(method, 0);
      if (slot0 >= 0) {
        sf->SetVReg(static_cast<size_t>(slot0), sf->GetVReg(static_cast<size_t>(slot0)) & ~kFlagSecure);
      }
      int slot1 = GetArgSlot(method, 1);
      if (slot1 >= 0) {
        sf->SetVReg(static_cast<size_t>(slot1), sf->GetVReg(static_cast<size_t>(slot1)) & ~kFlagSecure);
      }
      break;
    }
    case kCbSslPeerUnverifiedStepOut: {
      // SSLPeerUnverifiedException.<init>: if the caller is a void-returning method (a pinning-style
      // check that throws this exception directly), force it to return instead of throwing.
      ForceStepOutVoidCaller(self);
      break;
    }
    default:
      break;
  }
}
