# fuzz_digit known findings

Reproduce: `/mayhem/fuzz_digit-standalone <file>` (input = `[op][arg][payload]`; op%6==5 is the BigInt path).

1. `bigint-divide-hang.bin`: `BigInt<uint8_t,63>::Divide(remainder, divisor)` takes ~10 s (ASan, -O1) on this 26-byte
   input instead of returning promptly: the estimate-refinement loop (`BigInt.hpp:1340-1362`, via
   `SubtractBigInt` at `:1032`) steps by tiny corrections for certain dividend/divisor pairs built through the
   public shift/or API. A near-hang is a finding (DoS); the fuzz target does not guard it.
