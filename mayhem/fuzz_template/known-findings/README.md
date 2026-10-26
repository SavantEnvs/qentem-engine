# fuzz_template known findings

Reproduce: `/mayhem/fuzz_template-standalone <file>` (input = template text rendered against a fixed JSON value).

1. `stream-write-overflow.bin`, `copyto-render-1401-1713.bin`, `copyto-render-1401-1724.bin`, `copyto-render-1536.bin`,
   `copyto-render-1615.bin`: heap-buffer-overflow in `MemoryUtils::CopyTo` (`MemoryUtils.hpp:247`) called from
   `StringStreamBase::Write` (`StringStreamBase.hpp:217`) during `Template::Render` of a malformed `{math:...}` expression.
   The copy length/offset comes from an unchecked sub-expression range. Mayhem reports three distinct stacks; the file
   names give the `Template.hpp` render site that calls `Write`.
2. `getoperation-2314.bin`, `getoperation-2400.bin`, `getoperation-2423.bin`: `getOperation` (`Template.hpp:2314`, `:2400`,
   `:2423`) heap-buffer-overflow reads on a truncated `{math:...}` / `<if case=...>` expression.
3. `qexpression-teardown.bin` (and the input class `<loop set="~list" value="l"><if cas{var:l}</loop>{var:list[4][0]}`):
   teardown of a malformed `<if>` expression array (`QExpression::~QExpression`, `QExpression.hpp:79`, via
   `ArrayBase<QExpression>::End()`, `ArrayBase.hpp:383`) reads through a null/garbage array pointer.
4. `parsevariable-null-deref.bin`, `parsevariable-misaligned.bin`: `parseVariable` (`Template.hpp:1132`) dereferences a
   `LoopTag const*` that is null (SEGV at 0x53) or misaligned (UBSan `member access within misaligned address`).
