# fuzz_template_data known findings

Reproduce: `/mayhem/fuzz_template_data-standalone <file>` (input = `[flags][data_len BE16][JSON data][template]`;
`data_len` is taken modulo the remaining size; flags bit0 also renders through the `templates_cache` overload).
Every finding is a library defect reached from `Template::Render`; the file names give the failing site.

1. Malformed-expression parse sites, `Template.hpp:2314`, `:2400`, `:2423` (`getOperation`):
   `getoperation-2314.bin`, `getoperation-2400.bin`, `getoperation-2423.bin`. Heap-buffer-overflow reads on a
   truncated `{math:...}` / `<if case=...>` expression. Same family as the `fuzz_template` repros.
2. `StringStreamBase::Write` to `MemoryUtils::CopyTo` (`MemoryUtils.hpp:247`): `copyto-render-1536.bin`,
   `copyto-render-1615.bin`. Heap-buffer-overflow when the render step copies a sub-range that lies outside the template.
3. `qexpression-teardown.bin`: teardown of a malformed `<if>` expression array (`QExpression::~QExpression`,
   `QExpression.hpp:79`, via `ArrayBase<QExpression>::End()`/`~IfTagCase`) dereferences a null/garbage array pointer.
4. `parsevariable-misaligned.bin`: `parseVariable` (`Template.hpp:1132`) reads through a `LoopTag const*` that is null or
   misaligned (UBSan `member access within misaligned address`).
5. `destruct-tagbit-misaligned.bin`: `MemoryUtils::Destruct<Tags::TagBit>` (`MemoryUtils.hpp:328`), UBSan
   `member call on misaligned address`, first seen in this target.
6. `fast-string-to-number-overflow.bin`: `Digit::FastStringToNumber` (`Digit.hpp:428`), reached from `Value::GetValue`
   (`Value.hpp:1278`) while resolving an array index in a `{var:...}`: heap-buffer-overflow read. First seen here; it needs
   a data document whose array is indexed by a template key.
7. `json-literal-268.bin`, `json-literal-294.bin`: the JSON literal NUL bug (`JSON.hpp:268`, `:294`), reached through the
   data document. See `fuzz_json/known-findings`.
