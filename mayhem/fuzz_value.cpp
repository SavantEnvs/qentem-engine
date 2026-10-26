// Fuzz the Value tree API: parse two JSON documents, then apply a fuzzer-chosen stream of mutations,
// comparisons, lookups and ValuePath queries.
// Input: [n_ops & 15][n_ops op bytes][flags][split][JSON text]; the text is cut at split/256 into documents A and B.
#include <stddef.h>
#include <stdint.h>

#include "Qentem/JSON.hpp"
#include "Qentem/ValuePath.hpp"

using Qentem::JSON;
using Qentem::SizeT;
using Qentem::StringView;
using Qentem::ValuePath;
using ValueC = Qentem::Value<char>;

namespace {
const char *const kKeys[] = {"", "a", "name", "0", "k", "list", "id", "x.y"};

// Existing object keys give the lookups and removals real hits; otherwise a fixed key set.
struct Key {
    char  buf[64];
    SizeT len;

    Key(const ValueC &obj, uint8_t arg) noexcept : len{0} {
        const char *s = nullptr;
        SizeT       n = 0;

        if (((arg & 8U) != 0) && obj.IsObject() && (obj.Size() != 0)) {
            ValueC const    *val = nullptr;
            StringView<char> key{};
            obj.SetValueAndKeyAt(static_cast<SizeT>(arg & 7U) % obj.Size(), val, key);
            s = key.First();
            n = key.Length();
        } else {
            s = kKeys[arg & 7U];
            for (; s[n] != '\0'; ++n) {
            }
        }

        if (n > sizeof(buf)) {
            n = sizeof(buf);
        }
        for (SizeT i = 0; i < n; ++i) {
            buf[i] = s[i];
        }
        len = n;
    }

    StringView<char> View() const noexcept {
        return StringView<char>{buf, len};
    }
};

void Touch(const ValueC *v) {
    if (v != nullptr) {
        (void)v->Size();
        (void)v->Stringify();
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return -1;
    }

    const size_t n_ops = (data[0] & 15U);
    if ((n_ops + 3U) > size) {
        return -1;
    }

    const uint8_t *ops   = (data + 1);
    const uint8_t  flags = data[1 + n_ops];
    const size_t   split = data[2 + n_ops];
    const char    *text  = reinterpret_cast<const char *>(data + 3 + n_ops);
    const size_t   tlen  = (size - 3U - n_ops);
    const size_t   cut   = ((tlen * split) / 256U);

    ValueC a = ((flags & 1U) != 0) ? JSON::ParseWithComments(text, static_cast<SizeT>(cut))
                                   : JSON::Parse(text, static_cast<SizeT>(cut));
    ValueC b = ((flags & 2U) != 0) ? JSON::ParseWithComments(text + cut, static_cast<SizeT>(tlen - cut))
                                   : JSON::Parse(text + cut, static_cast<SizeT>(tlen - cut));

    for (size_t i = 0; i < n_ops; ++i) {
        const uint8_t op  = (ops[i] & 15U);
        const uint8_t arg = (ops[i] >> 4U);
        const Key     key{a, arg};

        switch (op) {
            case 0:
                a.Merge(b);
                break;

            case 1: {
                ValueC copy{b};
                a.Merge(static_cast<ValueC &&>(copy));
                break;
            }

            case 2: {
                ValueC grouped{};
                if (b.GroupBy(grouped, key.buf, key.len)) {
                    (void)grouped.Stringify();
                }
                break;
            }

            case 3:
                a.Remove(key.buf, key.len);
                break;

            case 4:
                a.RemoveAt(static_cast<SizeT>(arg));
                break;

            case 5: {
                ValueC copy{b};
                a.Insert(key.View(), static_cast<ValueC &&>(copy));
                break;
            }

            case 6:
                a[key.View()] = b;
                break;

            case 7:
                if ((arg & 1U) != 0) {
                    a[static_cast<SizeT>(arg)] = b;
                } else {
                    a[static_cast<SizeT>(arg)] = static_cast<Qentem::SizeT64>(arg);
                }
                break;

            case 8:
                a.RemoveExcessStorage();
                b.RemoveExcessStorage();
                break;

            case 9: {
                volatile bool r = ((a < b) ^ (a > b) ^ (a <= b) ^ (a >= b) ^ (a == b));
                (void)r;
                break;
            }

            case 10:
                Touch(a.GetValue(key.buf, key.len));
                Touch(static_cast<const ValueC &>(b).GetValue(key.View()));
                break;

            case 11: {
                const Key k2{b, static_cast<uint8_t>(arg ^ 9U)};
                const Key k3{a, static_cast<uint8_t>(arg ^ 3U)};
                Touch(ValuePath::GetValue(a, key.View(), k2.View()));
                Touch(ValuePath::GetValue(a, key.View(), k2.View(), k3.View()));
                break;
            }

            case 12:
                if ((arg & 1U) != 0) {
                    a += b;
                } else {
                    a += static_cast<Qentem::SizeT64>(arg);
                }
                break;

            case 13: {
                ValueC tmp{static_cast<ValueC &&>(a)};
                a = static_cast<ValueC &&>(b);
                b = static_cast<ValueC &&>(tmp);
                break;
            }

            case 14:
                a.Sort((arg & 1U) != 0);
                break;

            default:
                if ((arg & 1U) != 0) {
                    a = b;
                } else {
                    b.Reset();
                }
                break;
        }
    }

    (void)a.Stringify();
    (void)b.Stringify(2);

    return 0;
}
