#ifndef ART_OPENJDKJVMTI_RULE_INDEX_H_
#define ART_OPENJDKJVMTI_RULE_INDEX_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/locks.h"
#include "mirror/class.h"
#include "mirror/object.h"
#include "obj_ptr.h"

namespace art {
class ArtMethod;
}

namespace openjdkjvmti {

class RuleIndex {
 public:
  static void LoadFromBuffer(const uint8_t* data, size_t len);

  static bool Active();

  static bool ArgActive();

  static bool MightMatch(art::ObjPtr<art::mirror::Class> klass)
      REQUIRES_SHARED(art::Locks::mutator_lock_);

  // pending_regex: (pattern, haystack) for String args only. Non-String regex
  // predicates fail-open (return true) — never JNI toString from a BP callback.
  static bool ArgsMightMatch(art::ArtMethod* method,
                             art::ObjPtr<art::mirror::Object> return_value,
                             bool return_is_ref,
                             bool is_method_exit,
                             std::vector<std::pair<std::string, std::string>>* pending_regex)
      REQUIRES_SHARED(art::Locks::mutator_lock_);

  static void RecordArgDecision(bool forward);
};

}

#endif
