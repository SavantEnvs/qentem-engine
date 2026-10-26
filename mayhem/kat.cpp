// Known-answer probe: prints Qentem results for fixed inputs so mayhem/test.sh can assert exact values.
#include <stdio.h>

#include "Qentem/JSON.hpp"
#include "Qentem/StringStream.hpp"
#include "Qentem/Template.hpp"

using namespace Qentem;

static void put(const char *label, const char *s, unsigned n) {
    printf("%s=%.*s\n", label, static_cast<int>(n), s);
}

int main() {
    const Value<char> v = JSON::Parse(R"({"a": [1, 2.5, "x\ty", null, true], "b": {"k": -7}, "s": "q"})");

    const String<char> j = v.Stringify();
    put("json", j.First(), j.Length());

    StringStream<char> ss;
    const char         tpl[] = "{var:s}|{var:b[k]}|{var:a[1]}|{math:2+3*4}|{if case=\"1==1\" true=\"yes\" false=\"no\"}|"
                               "<loop set=\"a\" value=\"x\">{var:x},</loop>|<if case=\"{var:b[k]} < 0\">neg</if>";
    Template::Render(tpl, static_cast<SizeT>(sizeof(tpl) - 1U), v, ss);
    put("tpl", ss.First(), ss.Length());

    ss.Clear();
    Digit::NumberToString(ss, static_cast<SizeT64>(18446744073709551615ULL));
    ss.Write("|", 1);
    Digit::NumberToString(ss, static_cast<SizeT64I>(-1234567890123LL));
    ss.Write("|", 1);
    Digit::NumberToString(ss, 3.14159, Digit::RealFormatInfo{3U, Digit::RealFormatType::Fixed});
    put("num", ss.First(), ss.Length());

    QNumber64         n{};
    const char        in[] = "-42";
    SizeT             off  = 0;
    const QNumberType t    = Digit::StringToNumber(n, in, off, 3U);
    printf("parse=%d:%lld\n", static_cast<int>(t), static_cast<long long>(n.Integer));

    StringStream<char> es;
    JSONUtils::Escape("a\"b\n", 4U, es);
    put("esc", es.First(), es.Length());

    return 0;
}
