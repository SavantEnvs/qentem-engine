# fuzz_json known findings

Reproduce: `/mayhem/fuzz_json-standalone <file>` (inputs are `[flags byte][JSON text]`; flags bit0 = ParseWithComments).

1. `literal-true-nul.bin` (`[true\0]`): `JSON::parse` (`Include/Qentem/JSON.hpp:294`) global-buffer-overflow read.
   The literal-match loop `while ((++offset < length) && (content[offset] == *true_string)) ++true_string;`
   matches the NUL terminator of `"true"` against a NUL byte in the input and then advances `true_string` past the
   end of the constant. Fix: stop the loop when `*true_string == 0` (same pattern for `false`/`null`).
2. `unescape-trailing-backslash.bin`: `JSONUtils::UnEscape` (`Include/Qentem/JSONUtils.hpp:93`) heap-buffer-overflow
   read, reached from `JSON::parse` (`JSON.hpp:208`). A string whose body ends in a lone `\` reads `content[offset]`
   one past `length`. Fix: bounds-check `offset < length` after consuming the backslash.
