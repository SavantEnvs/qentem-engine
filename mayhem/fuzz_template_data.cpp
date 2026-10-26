// Fuzz Template::Render with fuzzed data AND a fuzzed template, including the templates_cache overload.
// Input: [flags][data_len_hi][data_len_lo][JSON data text][template text]; data_len is taken modulo the remaining size.
#include <stddef.h>
#include <stdint.h>

#include "Qentem/JSON.hpp"
#include "Qentem/Template.hpp"

using Qentem::Array;
using Qentem::JSON;
using Qentem::SizeT;
using Qentem::StringStream;
using Qentem::Template;
using Qentem::TemplateData;
using Qentem::TemplateDataCache;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return -1;
    }

    const uint8_t flags = data[0];
    const size_t  rest  = (size - 3U);
    const size_t  dlen  = (((static_cast<size_t>(data[1]) << 8U) | data[2]) % (rest + 1U));
    const char   *djson = reinterpret_cast<const char *>(data + 3);
    const char   *tpl   = (djson + dlen);
    const size_t  tlen  = (rest - dlen);

    const Qentem::Value<char> value = JSON::Parse(djson, static_cast<SizeT>(dlen));

    StringStream<char> ss;
    Template::Render(tpl, static_cast<SizeT>(tlen), value, ss);

    if ((flags & 1U) != 0) {
        // Cached path: the template cut into a main part and up to two sub templates ({st:key} selects one by ID).
        const size_t p1 = ((tlen * ((flags >> 1U) & 63U)) / 63U);
        const size_t p2 = (p1 + (((tlen - p1) * ((flags >> 7U) + 1U)) / 2U));

        TemplateData<char> main_t{tpl, static_cast<SizeT>(p1), 0};
        TemplateData<char> subs[2]{{tpl + p1, static_cast<SizeT>(p2 - p1), 1}, {tpl + p2, static_cast<SizeT>(tlen - p2), 2}};

        Array<TemplateDataCache<char>> cache{};
        StringStream<char>             out1;
        StringStream<char>             out2;

        Template::Render(out1, cache, value, &main_t, subs, SizeT{2});
        // Second render hits the already-parsed cache entries.
        Template::Render(out2, cache, value, &main_t, subs, SizeT{2});
    }

    return 0;
}
