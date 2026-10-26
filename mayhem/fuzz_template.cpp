// Fuzz Template::Render: attacker-controlled template text rendered against a fixed JSON value.
#include <stddef.h>
#include <stdint.h>

#include "Qentem/JSON.hpp"
#include "Qentem/Template.hpp"

using Qentem::JSON;
using Qentem::SizeT;
using Qentem::StringStream;
using Qentem::Template;

static const char kJson[] =
    R"({"name": "Qentem", "n": 7, "neg": -3, "real": 1.5, "t": true, "f": false, "nil": null,
        "list": [1, 2, 3, "x", [10, 20], {"k": "v"}],
        "objs": [{"id": 1, "tag": "a"}, {"id": 2, "tag": "b"}, {"id": 3, "tag": "c"}],
        "map": {"one": 1, "two": 2, "three": 3},
        "html": "<b>&amp;\"quote\"</b>"})";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Leaked on purpose: a static with a destructor would run ~Value() at process exit, which is a
    // harness artifact (no frame under LLVMFuzzerTestOneInput), not a library defect.
    static const Qentem::Value<char> &value = *new Qentem::Value<char>(JSON::Parse(kJson));

    if (size == 0) {
        return -1;
    }

    const char *content = reinterpret_cast<const char *>(data);

    StringStream<char> ss;
    Template::Render(content, static_cast<SizeT>(size), value, ss);

    return 0;
}
