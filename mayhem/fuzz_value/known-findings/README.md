# fuzz_value known findings

Reproduce: `/mayhem/fuzz_value-standalone <file>` (input = `[n_ops & 15][n_ops op bytes][flags][split][JSON text]`; the
text is cut at `split/256` into documents A and B, then the op bytes drive Merge/GroupBy/Remove/Insert/operator[]/
comparisons/GetValue/ValuePath on them). All findings below are in the JSON parser the harness reaches first; the
Value-tree operations themselves reported no defect in the 300 s confirmation run.

1. `json-literal-268.bin`, `json-literal-272.bin`, `json-literal-294.bin`: `JSON::parse` (`JSON.hpp:268`, `:272`, `:294`).
   The `false`/`null`/`true` literal-match loops compare the NUL terminator of the constant against a NUL byte in the
   input, then read past the constant (UBSan `load of address ... insufficient space`). Same bug as
   `fuzz_json/known-findings/literal-true-nul.bin`. Fix: stop when `*literal == 0`.
2. `unescape-trailing-backslash.bin`: `JSONUtils::UnEscape` (`JSONUtils.hpp:93`) heap-buffer-overflow read on a string
   that ends in a lone `\`. Same bug as `fuzz_json`/`fuzz_text`.
3. `unescape-short-hex.bin`: `Digit::HexStringToNumber` (`Digit.hpp:193`), called from `JSONUtils::UnEscape`
   (`JSONUtils.hpp:133`) for a `\u` escape cut short by the end of the string: heap-buffer-overflow read. First seen in
   this target. Fix: bound the hex-digit count by the remaining length.
