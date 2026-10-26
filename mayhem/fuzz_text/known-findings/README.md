# fuzz_text known findings

Reproduce: `/mayhem/fuzz_text-standalone <file>` (input = `[op][payload]`; op%5==0 is UnEscape).

1. `unescape-trailing-backslash.bin`: `JSONUtils::UnEscape(content, length, stream)` reads `content[length]` when the
   last byte is `\` (`JSONUtils.hpp:93`, heap-buffer-overflow read). Same root cause as fuzz_json finding 2.
