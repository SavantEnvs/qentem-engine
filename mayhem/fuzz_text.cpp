// Fuzz string utilities: JSON escape/unescape, comment stripping and unicode encoding.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Qentem/JSONUtils.hpp"
#include "Qentem/StringStream.hpp"
#include "Qentem/StringUtils.hpp"
#include "Qentem/Unicode.hpp"

using namespace Qentem;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }

    const uint8_t op      = data[0];
    const char   *content = reinterpret_cast<const char *>(data + 1);
    const SizeT   length  = static_cast<SizeT>(size - 1);

    switch (op % 5U) {
        case 0: {
            StringStream<char> ss;
            (void)JSONUtils::UnEscape(content, length, ss);
            break;
        }
        case 1: {
            StringStream<char> ss;
            JSONUtils::Escape(content, length, ss);
            StringStream<char> back;
            const SizeT        n = JSONUtils::UnEscape(ss.First(), ss.Length(), back);
            (void)n;
            break;
        }
        case 2: {
            // StripComments edits the buffer in place; give it an exact-size heap copy so ASan sees overruns.
            char *copy = new char[length];
            memcpy(copy, content, length);
            StringUtils::StripComments(copy, length);
            delete[] copy;
            break;
        }
        case 3: {
            uint32_t code = 0;
            memcpy(&code, content, length < 4U ? length : 4U);
            code %= 0x110000U;
            if ((code >= 0xD800U) && (code <= 0xDFFFU)) {
                return -1;
            }
            StringStream<char>     s8;
            StringStream<char16_t> s16;
            StringStream<char32_t> s32;
            Unicode::ToUTF<char>(code, s8);
            Unicode::ToUTF<char16_t>(code, s16);
            Unicode::ToUTF<char32_t>(code, s32);
            break;
        }
        default: {
            SizeT offset = 0;
            SizeT len    = length;
            StringUtils::Trim(content, offset, len);
            (void)StringUtils::Hash(content + offset, len);
            break;
        }
    }

    return 0;
}
