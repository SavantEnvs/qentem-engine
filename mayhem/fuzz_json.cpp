// Fuzz JSON::Parse / JSON::ParseWithComments, then walk, sort, stringify and re-parse the result.
#include <stddef.h>
#include <stdint.h>

#include "Qentem/JSON.hpp"

using Qentem::JSON;
using Qentem::SizeT;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }

    const bool  comments = ((data[0] & 1U) != 0);
    const char *content  = reinterpret_cast<const char *>(data + 1);
    const SizeT length   = static_cast<SizeT>(size - 1);

    Qentem::Value<char> value = comments ? JSON::ParseWithComments(content, length) : JSON::Parse(content, length);

    if (value.IsUndefined()) {
        return -1;
    }

    const SizeT n = value.Size();
    for (SizeT i = 0; (i < n) && (i < 64U); ++i) {
        const Qentem::Value<char> *item = value.GetValueAt(i);
        if (item != nullptr) {
            (void)item->Stringify();
        }
    }

    value.Sort((data[0] & 2U) != 0);

    const Qentem::String<char> out = value.Stringify();
    Qentem::Value<char>        again = JSON::Parse(out.First(), out.Length());
    (void)again.Stringify(3);

    return 0;
}
