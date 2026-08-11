/* See rule_index.h. */

#include "rule_index.h"

#include <atomic>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "android-base/logging.h"

#include "art_field-inl.h"
#include "art_method-inl.h"
#include "base/pointer_size.h"
#include "base/leb128.h"
#include "dex/dex_file.h"
#include "dex/dex_file_structs.h"
#include "dex/dex_file_types.h"
#include "arch/context.h"
#include "dex/code_item_accessors-inl.h"
#include "jni/jni_env_ext-inl.h"
#include "mirror/class-inl.h"
#include "mirror/object-inl.h"
#include "mirror/string.h"
#include "stack.h"
#include "thread.h"

namespace openjdkjvmti {

namespace {

struct ArgPredicate {
  std::string position;
  bool is_regex = false;
  bool is_number = false;
  bool case_sensitive = false;
  bool null_matches = false;
  std::vector<std::pair<int, int>> arity_ranges;
  std::vector<std::pair<int, int>> number_ranges;
  std::vector<std::string> literals;
};

struct IndexData {
  bool class_active = false;
  std::unordered_set<std::string> class_exact;
  std::vector<std::string> class_prefix;
  std::vector<std::string> class_substrings;
  std::unordered_set<std::string> method_names;
  std::unordered_set<std::string> field_names;
  std::unordered_set<std::string> annotation_descriptors;
  bool check_substrings = false;
  bool check_methods = false;
  bool check_fields = false;
  bool check_annotations = false;

  bool arg_active = false;
  std::unordered_map<std::string, std::vector<ArgPredicate>> arg_predicates;
  std::unordered_set<std::string> arg_predicate_methods;
};

std::string DottedClassName(const std::string& descriptor) {
  if (descriptor.size() < 2 || descriptor.front() != 'L' || descriptor.back() != ';') {
    return std::string();
  }
  std::string dotted = descriptor.substr(1, descriptor.size() - 2);
  for (char& ch : dotted) {
    if (ch == '/' || ch == '$') {
      ch = '.';
    }
  }
  return dotted;
}

IndexData* g_index = nullptr;

bool HasPrefix(const std::string& s, const std::vector<std::string>& prefixes) {
  for (const std::string& p : prefixes) {
    if (s.size() >= p.size() && s.compare(0, p.size(), p) == 0) {
      return true;
    }
  }
  return false;
}

bool ContainsAny(const std::string& haystack, const std::vector<std::string>& needles) {
  for (const std::string& needle : needles) {
    if (haystack.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool MatchesSubstring(const std::string& descriptor, const std::vector<std::string>& substrings)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  if (descriptor.size() < 2 || descriptor.front() != 'L' || descriptor.back() != ';') {
    return false;
  }
  std::string dotted = descriptor.substr(1, descriptor.size() - 2);
  bool has_dollar = false;
  for (char& ch : dotted) {
    if (ch == '/') {
      ch = '.';
    } else if (ch == '$') {
      has_dollar = true;
    }
  }
  if (ContainsAny(dotted, substrings)) {
    return true;
  }
  if (has_dollar) {
    for (char& ch : dotted) {
      if (ch == '$') {
        ch = '.';
      }
    }
    return ContainsAny(dotted, substrings);
  }
  return false;
}

bool ClassHasAnnotatedMethod(const art::DexFile* dex, const art::dex::ClassDef& class_def,
                             const std::unordered_set<std::string>& annotations)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  const art::dex::AnnotationsDirectoryItem* dir = dex->GetAnnotationsDirectory(class_def);
  if (dir == nullptr) {
    return false;
  }
  const art::dex::MethodAnnotationsItem* method_annotations = dex->GetMethodAnnotations(dir);
  if (method_annotations == nullptr) {
    return false;
  }
  for (uint32_t i = 0, n = dir->methods_size_; i < n; ++i) {
    const art::dex::AnnotationSetItem* set = dex->GetMethodAnnotationSetItem(method_annotations[i]);
    if (set == nullptr) {
      continue;
    }
    for (uint32_t j = 0; j < set->size_; ++j) {
      const art::dex::AnnotationItem* item = dex->GetAnnotationItem(set, j);
      if (item == nullptr) {
        continue;
      }
      const uint8_t* p = item->annotation_;
      const uint32_t type_idx_u = art::DecodeUnsignedLeb128(&p);
      art::dex::TypeIndex type_idx(static_cast<uint16_t>(type_idx_u));
      const char* descriptor = dex->GetTypeDescriptor(type_idx);
      if (descriptor != nullptr && annotations.find(descriptor) != annotations.end()) {
        return true;
      }
    }
  }
  return false;
}

enum MatchReason {
  kReasonClassExact = 0,
  kReasonClassPrefix,
  kReasonClassSubstring,
  kReasonMethod,
  kReasonAnnotation,
  kReasonField,
  kReasonUnresolved,
  kReasonCount,
  kReasonNone = -1,
};

int SelfMatches(art::ObjPtr<art::mirror::Class> klass, const IndexData& idx)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  std::string storage;
  std::string descriptor(klass->GetDescriptor(&storage));
  if (idx.class_exact.find(descriptor) != idx.class_exact.end()) {
    return kReasonClassExact;
  }
  if (HasPrefix(descriptor, idx.class_prefix)) {
    return kReasonClassPrefix;
  }
  if (idx.check_substrings && MatchesSubstring(descriptor, idx.class_substrings)) {
    return kReasonClassSubstring;
  }
  if (idx.check_methods) {
    for (art::ArtMethod& m : klass->GetMethods(art::kRuntimePointerSize)) {
      const char* name = m.GetName();
      if (name != nullptr && idx.method_names.find(name) != idx.method_names.end()) {
        return kReasonMethod;
      }
    }
  }
  if (idx.check_annotations) {
    const art::dex::ClassDef* class_def = klass->GetClassDef();
    if (class_def != nullptr) {
      if (ClassHasAnnotatedMethod(&klass->GetDexFile(), *class_def, idx.annotation_descriptors)) {
        return kReasonAnnotation;
      }
    }
  }
  if (idx.check_fields) {
    for (art::ArtField& f : klass->GetFields()) {
      const char* name = f.GetName();
      if (name != nullptr && idx.field_names.find(name) != idx.field_names.end()) {
        return kReasonField;
      }
    }
  }
  return kReasonNone;
}

bool EvaluateExact(const ArgPredicate& p, const std::string& value) {
  for (const std::string& lit : p.literals) {
    if (value == lit) {
      return true;
    }
  }
  return false;
}

std::vector<std::pair<int, int>> ParseRanges(const std::string& spec) {
  std::vector<std::pair<int, int>> ranges;
  if (spec.empty() || spec == "*") {
    return ranges;
  }
  size_t start = 0;
  while (start <= spec.size()) {
    size_t comma = spec.find(',', start);
    std::string tok = spec.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
    if (!tok.empty()) {
      size_t dash = tok.find('-');
      if (dash == std::string::npos) {
        int v = std::atoi(tok.c_str());
        ranges.emplace_back(v, v);
      } else if (dash == 0) {
        ranges.emplace_back(INT_MIN, std::atoi(tok.c_str() + 1));
      } else if (dash + 1 == tok.size()) {
        ranges.emplace_back(std::atoi(tok.c_str()), INT_MAX);
      } else {
        ranges.emplace_back(std::atoi(tok.substr(0, dash).c_str()), std::atoi(tok.c_str() + dash + 1));
      }
    }
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  return ranges;
}

bool RangesMatch(const std::vector<std::pair<int, int>>& ranges, int value) {
  for (const std::pair<int, int>& r : ranges) {
    if (value >= r.first && value <= r.second) {
      return true;
    }
  }
  return false;
}

class TopFrameRefReader final : public art::StackVisitor {
 public:
  TopFrameRefReader(art::Thread* thread, art::Context* context, uint16_t slot)
      : art::StackVisitor(thread, context, art::StackVisitor::StackWalkKind::kIncludeInlinedFrames),
        slot_(slot) {}

  bool VisitFrame() override REQUIRES_SHARED(art::Locks::mutator_lock_) {
    art::ArtMethod* m = GetMethod();
    if (m == nullptr || m->IsRuntimeMethod()) {
      return true;
    }
    if (!m->IsNative() && !m->IsProxyMethod() && GetDexPc(false) == 0) {
      uint32_t ptr_val = 0;
      if (GetVReg(m, slot_, art::kReferenceVReg, &ptr_val)) {
        obj_ = reinterpret_cast<art::mirror::Object*>(ptr_val);
        ok_ = true;
      }
    }
    return false;
  }

  bool ok_ = false;
  art::mirror::Object* obj_ = nullptr;

 private:
  const uint16_t slot_;
};

int EntryArgSlot(art::ArtMethod* method, const std::string& position)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  uint16_t num_regs = method->DexInstructionData().RegistersSize();
  uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return -1;
  }
  int first_arg = static_cast<int>(num_regs) - static_cast<int>(ins);
  bool is_static = method->IsStatic();
  if (position == "this") {
    return is_static ? -1 : first_arg;
  }
  if (position.size() <= 3 || position.compare(0, 3, "arg") != 0) {
    return -1;
  }
  int idx = std::atoi(position.c_str() + 3);
  if (idx < 0) {
    return -1;
  }
  const char* shorty = method->GetShorty();
  if (shorty == nullptr) {
    return -1;
  }
  int slot = first_arg + (is_static ? 0 : 1);
  int param = 0;
  for (size_t s = 1; shorty[s] != '\0'; ++s) {
    if (param == idx) {
      return slot;
    }
    slot += (shorty[s] == 'J' || shorty[s] == 'D') ? 2 : 1;
    ++param;
  }
  return -1;
}

int EntryArgSlotTyped(art::ArtMethod* method, const std::string& position, char* type)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  *type = 0;
  if (position.size() <= 3 || position.compare(0, 3, "arg") != 0) {
    return -1;
  }
  uint16_t num_regs = method->DexInstructionData().RegistersSize();
  uint16_t ins = method->DexInstructionData().InsSize();
  if (ins > num_regs) {
    return -1;
  }
  int idx = std::atoi(position.c_str() + 3);
  if (idx < 0) {
    return -1;
  }
  bool is_static = method->IsStatic();
  const char* shorty = method->GetShorty();
  if (shorty == nullptr) {
    return -1;
  }
  int slot = static_cast<int>(num_regs) - static_cast<int>(ins) + (is_static ? 0 : 1);
  int param = 0;
  for (size_t s = 1; shorty[s] != '\0'; ++s) {
    if (param == idx) {
      *type = shorty[s];
      return slot;
    }
    slot += (shorty[s] == 'J' || shorty[s] == 'D') ? 2 : 1;
    ++param;
  }
  return -1;
}

class TopFrameIntReader final : public art::StackVisitor {
 public:
  TopFrameIntReader(art::Thread* thread, art::Context* context, uint16_t slot, bool is_long)
      : art::StackVisitor(thread, context, art::StackVisitor::StackWalkKind::kIncludeInlinedFrames),
        slot_(slot), is_long_(is_long) {}

  bool VisitFrame() override REQUIRES_SHARED(art::Locks::mutator_lock_) {
    art::ArtMethod* m = GetMethod();
    if (m == nullptr || m->IsRuntimeMethod()) {
      return true;
    }
    if (!m->IsNative() && !m->IsProxyMethod() && GetDexPc(false) == 0) {
      if (is_long_) {
        uint64_t pair = 0;
        if (GetVRegPair(m, slot_, art::kLongLoVReg, art::kLongHiVReg, &pair)) {
          val_ = static_cast<int32_t>(static_cast<int64_t>(pair));
          ok_ = true;
        }
      } else {
        uint32_t v = 0;
        if (GetVReg(m, slot_, art::kIntVReg, &v)) {
          val_ = static_cast<int32_t>(v);
          ok_ = true;
        }
      }
    }
    return false;
  }

  bool ok_ = false;
  int32_t val_ = 0;

 private:
  const uint16_t slot_;
  const bool is_long_;
};

bool ReadParamValue(const ArgPredicate& p, art::Thread* self, art::ArtMethod* method,
                    art::ObjPtr<art::mirror::Object> return_value, bool return_is_ref,
                    bool is_method_exit, bool* evaluable, bool* is_null,
                    art::ObjPtr<art::mirror::Object>* out)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  *evaluable = true;
  *is_null = false;
  art::ObjPtr<art::mirror::Object> value;
  if (p.position == "ret") {
    if (!is_method_exit || !return_is_ref) {
      *evaluable = false;
      return false;
    }
    value = return_value;
  } else {
    if (is_method_exit) {
      *evaluable = false;
      return false;
    }
    int slot = EntryArgSlot(method, p.position);
    if (slot < 0) {
      *evaluable = false;
      return false;
    }
    std::unique_ptr<art::Context> context(art::Context::Create());
    TopFrameRefReader reader(self, context.get(), static_cast<uint16_t>(slot));
    reader.WalkStack();
    if (!reader.ok_) {
      *evaluable = false;
      return false;
    }
    value = reader.obj_;
  }
  if (value == nullptr) {
    *is_null = true;
    return false;
  }
  *out = value;
  return true;
}

void CollectArgPredicates(art::ObjPtr<art::mirror::Class> klass, const std::string& method_name,
                          const IndexData& idx, std::vector<const ArgPredicate*>* out)
    REQUIRES_SHARED(art::Locks::mutator_lock_) {
  auto wildcard = idx.arg_predicates.find("*\t" + method_name);
  if (wildcard != idx.arg_predicates.end()) {
    for (const ArgPredicate& p : wildcard->second) {
      out->push_back(&p);
    }
  }
  std::vector<art::ObjPtr<art::mirror::Class>> worklist;
  std::unordered_set<const void*> visited;
  worklist.push_back(klass);
  size_t guard = 0;
  while (!worklist.empty()) {
    if (++guard > 4096) {
      break;
    }
    art::ObjPtr<art::mirror::Class> c = worklist.back();
    worklist.pop_back();
    if (c == nullptr || !visited.insert(c.Ptr()).second) {
      continue;
    }
    std::string storage;
    std::string dotted = DottedClassName(c->GetDescriptor(&storage));
    if (!dotted.empty()) {
      auto it = idx.arg_predicates.find(dotted + '\t' + method_name);
      if (it != idx.arg_predicates.end()) {
        for (const ArgPredicate& p : it->second) {
          out->push_back(&p);
        }
      }
    }
    art::ObjPtr<art::mirror::Class> super = c->GetSuperClass();
    if (super != nullptr) {
      worklist.push_back(super);
    }
    uint32_t num_ifaces = c->NumDirectInterfaces();
    for (uint32_t i = 0; i < num_ifaces; ++i) {
      art::ObjPtr<art::mirror::Class> iface = c->GetDirectInterface(i);
      if (iface != nullptr) {
        worklist.push_back(iface);
      }
    }
  }
}

}

void RuleIndex::LoadFromBuffer(const uint8_t* bytes, size_t len) {
  if (g_index != nullptr) {
    return;
  }
  struct Reader {
    const uint8_t* data;
    size_t len;
    size_t pos = 0;
    bool ok = true;
    uint8_t U8() {
      if (pos + 1 > len) { ok = false; return 0; }
      return data[pos++];
    }
    uint32_t U32() {
      if (pos + 4 > len) { ok = false; return 0; }
      uint32_t v = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16)
                 | (uint32_t(data[pos + 2]) << 8) | uint32_t(data[pos + 3]);
      pos += 4;
      return v;
    }
    std::string Str() {
      uint32_t n = U32();
      if (!ok || pos + n > len) { ok = false; return std::string(); }
      std::string s(reinterpret_cast<const char*>(data + pos), n);
      pos += n;
      return s;
    }
  };
  Reader r{bytes, len};
  if (r.U32() != 0x44415354u || r.U8() != 1u) {
    return;
  }

  IndexData* data = new IndexData();

  bool complete = (r.U8() != 0);
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->class_exact.insert(r.Str());
  }
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->class_prefix.push_back(r.Str());
  }
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->class_substrings.push_back(r.Str());
  }
  data->check_substrings = !data->class_substrings.empty();
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->method_names.insert(r.Str());
  }
  data->check_methods = !data->method_names.empty();
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->field_names.insert(r.Str());
  }
  data->check_fields = !data->field_names.empty();
  for (uint32_t n = r.U32(), i = 0; r.ok && i < n; i++) {
    data->annotation_descriptors.insert(r.Str());
  }
  data->check_annotations = !data->annotation_descriptors.empty();

  bool arg_complete = (r.U8() != 0);
  for (uint32_t rules = r.U32(), ri = 0; r.ok && ri < rules; ri++) {
    std::string class_key = r.Str();
    std::string method = r.Str();
    std::string key = class_key + '\t' + method;
    data->arg_predicate_methods.insert(method);
    for (uint32_t preds = r.U32(), pi = 0; r.ok && pi < preds; pi++) {
      ArgPredicate p;
      p.position = r.Str();
      uint8_t flags = r.U8();
      p.is_regex = (flags & 0x1) != 0;
      p.is_number = (flags & 0x2) != 0;
      p.case_sensitive = (flags & 0x4) != 0;
      p.null_matches = (flags & 0x8) != 0;
      p.arity_ranges = ParseRanges(r.Str());
      for (uint32_t lits = r.U32(), li = 0; r.ok && li < lits; li++) {
        p.literals.push_back(r.Str());
      }
      if (p.is_number) {
        p.number_ranges = p.literals.empty() ? std::vector<std::pair<int, int>>()
                                             : ParseRanges(p.literals[0]);
      }
      bool usable = p.is_number ? !p.number_ranges.empty() : !p.literals.empty();
      if (r.ok && !p.position.empty() && usable) {
        data->arg_predicates[key].push_back(std::move(p));
      }
    }
  }

  if (!r.ok) {
    delete data;
    return;
  }
  data->class_active = complete;
  data->arg_active = arg_complete;
  if (!data->class_active && !data->arg_active) {
    delete data;
    return;
  }
  g_index = data;
}

bool RuleIndex::Active() {
  return g_index != nullptr && g_index->class_active;
}

bool RuleIndex::ArgActive() {
  return g_index != nullptr && g_index->arg_active;
}

bool RuleIndex::MightMatch(art::ObjPtr<art::mirror::Class> klass) {
  const IndexData* idx = g_index;
  if (idx == nullptr || !idx->class_active || klass == nullptr) {
    return true;
  }

  int reason = kReasonNone;
  std::vector<art::ObjPtr<art::mirror::Class>> worklist;
  std::unordered_set<const void*> visited;
  worklist.push_back(klass);
  size_t guard = 0;
  while (!worklist.empty()) {
    if (++guard > 4096) {
      reason = kReasonUnresolved;
      break;
    }
    art::ObjPtr<art::mirror::Class> c = worklist.back();
    worklist.pop_back();
    if (!visited.insert(c.Ptr()).second) {
      continue;
    }
    int self = SelfMatches(c, *idx);
    if (self != kReasonNone) {
      reason = self;
      break;
    }
    art::ObjPtr<art::mirror::Class> super = c->GetSuperClass();
    if (super != nullptr) {
      worklist.push_back(super);
    }
    uint32_t num_ifaces = c->NumDirectInterfaces();
    bool unresolved = false;
    for (uint32_t i = 0; i < num_ifaces; ++i) {
      art::ObjPtr<art::mirror::Class> iface = c->GetDirectInterface(i);
      if (iface == nullptr) {
        unresolved = true;
        break;
      }
      worklist.push_back(iface);
    }
    if (unresolved) {
      reason = kReasonUnresolved;
      break;
    }
  }

  const bool result = (reason != kReasonNone);

  /* RuleIndex stats logging disabled
  static std::atomic<uint64_t> g_reason_counts[kReasonCount] = {};
  static std::atomic<uint64_t> g_dropped{0};
  static std::atomic<uint64_t> g_total{0};
  if (result) {
    g_reason_counts[reason].fetch_add(1, std::memory_order_relaxed);
  } else {
    g_dropped.fetch_add(1, std::memory_order_relaxed);
  }
  const uint64_t total = g_total.fetch_add(1, std::memory_order_relaxed) + 1;
  if (total == 1 || total % 500 == 0) {
    const uint64_t exact = g_reason_counts[kReasonClassExact].load(std::memory_order_relaxed);
    const uint64_t prefix = g_reason_counts[kReasonClassPrefix].load(std::memory_order_relaxed);
    const uint64_t substr = g_reason_counts[kReasonClassSubstring].load(std::memory_order_relaxed);
    const uint64_t method = g_reason_counts[kReasonMethod].load(std::memory_order_relaxed);
    const uint64_t annotation = g_reason_counts[kReasonAnnotation].load(std::memory_order_relaxed);
    const uint64_t field = g_reason_counts[kReasonField].load(std::memory_order_relaxed);
    const uint64_t unresolved = g_reason_counts[kReasonUnresolved].load(std::memory_order_relaxed);
    const uint64_t dropped = g_dropped.load(std::memory_order_relaxed);
    LOG(WARNING) << "DAST RuleIndex totals: processed=" << total << " forwarded=" << (total - dropped)
                 << " [className=" << (exact + prefix + substr)
                 << "(exact=" << exact << " prefix=" << prefix << " substring=" << substr << ")"
                 << " method=" << method << " annotation=" << annotation << " field=" << field
                 << " unresolved=" << unresolved << "]"
                 << " dropped(negFilter)=" << dropped;
  }
  */
  return result;
}

bool RuleIndex::ArgsMightMatch(art::ArtMethod* method,
                               art::ObjPtr<art::mirror::Object> return_value,
                               bool return_is_ref,
                               bool is_method_exit,
                               std::vector<std::pair<std::string, std::string>>* pending_regex) {
  const IndexData* idx = g_index;
  if (idx == nullptr || !idx->arg_active || method == nullptr) {
    return true;
  }
  const char* name_c = method->GetName();
  if (name_c == nullptr) {
    return true;
  }
  std::string method_name(name_c);

  if (idx->arg_predicate_methods.find(method_name) == idx->arg_predicate_methods.end()) {
    return true;
  }

  std::vector<const ArgPredicate*> preds;
  CollectArgPredicates(method->GetDeclaringClass(), method_name, *idx, &preds);
  if (preds.empty()) {
    return true;
  }

  art::Thread* self = art::Thread::Current();
  const char* shorty = method->GetShorty();
  int trigger_arity = (shorty != nullptr) ? static_cast<int>(std::strlen(shorty)) - 1 : -1;

  for (const ArgPredicate* pp : preds) {
    const ArgPredicate& p = *pp;
    if (!p.arity_ranges.empty() && trigger_arity >= 0 && !RangesMatch(p.arity_ranges, trigger_arity)) {
      continue;
    }
    if (is_method_exit && p.position != "ret") {
      continue;
    }
    if (p.is_number) {
      char type = 0;
      int slot = EntryArgSlotTyped(method, p.position, &type);
      if (slot < 0) {
        continue;
      }
      bool is_long = (type == 'J');
      if (type != 'I' && type != 'B' && type != 'S' && type != 'C' && type != 'Z' && !is_long) {
        return true;
      }
      std::unique_ptr<art::Context> ctx(art::Context::Create());
      TopFrameIntReader reader(self, ctx.get(), static_cast<uint16_t>(slot), is_long);
      reader.WalkStack();
      if (!reader.ok_) {
        continue;
      }
      if (RangesMatch(p.number_ranges, reader.val_)) {
        return true;
      }
      continue;
    }
    bool evaluable = true;
    bool is_null = false;
    art::ObjPtr<art::mirror::Object> value;
    ReadParamValue(p, self, method, return_value, return_is_ref, is_method_exit,
                   &evaluable, &is_null, &value);
    if (!evaluable) {
      continue;
    }
    if (is_null) {
      if (p.null_matches) {
        return true;
      }
      continue;
    }
    if (p.is_regex) {
      // Safe path only: mirror String → UTF-8. Calling Java toString() from a
      // breakpoint/method-exit filter re-enters JVMTI/JDWP and deadlocks.
      if (!value->GetClass()->IsStringClass()) {
        return true;
      }
      if (pending_regex != nullptr) {
        pending_regex->emplace_back(p.literals.empty() ? std::string() : p.literals[0],
                                    value->AsString()->ToModifiedUtf8());
      } else {
        return true;
      }
      continue;
    }
    if (!value->GetClass()->IsStringClass()) {
      return true;
    }
    if (EvaluateExact(p, value->AsString()->ToModifiedUtf8())) {
      return true;
    }
  }

  return false;
}

void RuleIndex::RecordArgDecision(bool forward) {
  (void)forward;
  /* RuleIndex arg stats logging disabled
  static std::atomic<uint64_t> g_arg_forwarded{0};
  static std::atomic<uint64_t> g_arg_dropped{0};
  if (forward) {
    g_arg_forwarded.fetch_add(1, std::memory_order_relaxed);
  } else {
    g_arg_dropped.fetch_add(1, std::memory_order_relaxed);
  }
  const uint64_t fwd = g_arg_forwarded.load(std::memory_order_relaxed);
  const uint64_t drp = g_arg_dropped.load(std::memory_order_relaxed);
  const uint64_t total = fwd + drp;
  if (total == 1 || total % 500 == 0) {
    LOG(WARNING) << "DAST RuleIndex arg totals: triggers=" << total << " forwarded=" << fwd
                 << " dropped(inProcess)=" << drp;
  }
  */
}

}
