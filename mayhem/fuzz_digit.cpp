// Fuzz number parsing/formatting (Digit) and BigInt arithmetic.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Qentem/BigInt.hpp"
#include "Qentem/Digit.hpp"
#include "Qentem/StringStream.hpp"

using namespace Qentem;

template <typename Big_T>
static void bigOps(const uint8_t *data, size_t size, uint64_t k) {
    // Build both operands through the public API so internal state stays consistent.
    Big_T x{};
    Big_T y{};
    for (size_t i = 0; i < size; ++i) {
        Big_T &dst = (i < size / 2) ? x : y;
        dst <<= 8U;
        dst |= static_cast<uint8_t>(data[i]);
    }

    Big_T s{x};
    s += y;
    Big_T d{x};
    d -= y;

    typename Big_T::NumberType n = static_cast<typename Big_T::NumberType>(k | 1U);
    Big_T                      m{x};
    m *= n;
    Big_T q{x};
    (void)q.Divide(n);

    Big_T r{};
    Big_T dv{x};
    if (y.IsNotZero()) {
        dv.Divide(r, y);
    }

    Big_T p{};
    x.Multiply(p, y);

    (void)(x < y);
    (void)(x == y);
    (void)(x >= y);
    x <<= static_cast<SizeT32>(k & 63U);
    x >>= static_cast<SizeT32>((k >> 8U) & 63U);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }

    const uint8_t op      = data[0];
    const char   *content = reinterpret_cast<const char *>(data + 2);
    const SizeT   length  = static_cast<SizeT>(size - 2);
    const uint8_t arg     = data[1];

    switch (op % 6U) {
        case 0: { // string -> number -> string (64-bit)
            QNumber64 number{};
            SizeT     offset = 0;
            StringStream<char> ss;
            switch (Digit::StringToNumber(number, content, offset, length)) {
                case QNumberType::Natural: Digit::NumberToString(ss, number.Natural); break;
                case QNumberType::Integer: Digit::NumberToString(ss, number.Integer); break;
                case QNumberType::Real: {
                    Digit::RealFormatInfo info{arg % 20U, static_cast<Digit::RealFormatType>(arg % 3U)};
                    Digit::NumberToString(ss, number.Real, info);
                    break;
                }
                default: return -1;
            }
            break;
        }
        case 1: { // string -> number -> string (32-bit)
            QNumber32 number{};
            SizeT     offset = 0;
            StringStream<char> ss;
            switch (Digit::StringToNumber(number, content, offset, length)) {
                case QNumberType::Natural: Digit::NumberToString(ss, number.Natural); break;
                case QNumberType::Integer: Digit::NumberToString(ss, number.Integer); break;
                case QNumberType::Real: {
                    Digit::RealFormatInfo info{arg % 12U, static_cast<Digit::RealFormatType>(arg % 3U)};
                    Digit::NumberToString(ss, number.Real, info);
                    break;
                }
                default: return -1;
            }
            break;
        }
        case 2: { // raw bits -> double/float formatting
            uint64_t bits = 0;
            memcpy(&bits, content, length < 8U ? length : 8U);
            double d;
            memcpy(&d, &bits, sizeof(d));
            float f;
            const uint32_t b32 = static_cast<uint32_t>(bits);
            memcpy(&f, &b32, sizeof(f));
            StringStream<char> ss;
            Digit::RealFormatInfo info{arg % 24U, static_cast<Digit::RealFormatType>(arg % 3U)};
            Digit::NumberToString(ss, d, info);
            ss.Clear();
            Digit::NumberToString(ss, f, info);
            break;
        }
        case 3: { // hex
            (void)Digit::HexStringToNumber<SizeT64>(content, length);
            uint64_t bits = 0;
            memcpy(&bits, content, length < 8U ? length : 8U);
            char buffer[32];
            (void)Digit::NumberToHex(buffer, static_cast<SizeT64>(bits));
            break;
        }
        case 4: { // binary formatting
            uint64_t bits = 0;
            memcpy(&bits, content, length < 8U ? length : 8U);
            StringStream<char> ss;
            Digit::NumberToBinary(ss, bits, 1U + (arg % 16U));
            ss.Clear();
            Digit::StringToBinary(ss, content, length, 1U + (arg % 16U));
            break;
        }
        default: { // BigInt
            const uint8_t *p = data + 2;
            switch (arg % 4U) {
                case 0: bigOps<BigInt<SizeT64, 256U>>(p, length > 64 ? 64 : length, arg); break;
                case 1: bigOps<BigInt<SizeT32, 192U>>(p, length > 48 ? 48 : length, arg); break;
                case 2: bigOps<BigInt<SizeT16, 128U>>(p, length > 32 ? 32 : length, arg); break;
                default: bigOps<BigInt<SizeT8, 63U>>(p, length > 16 ? 16 : length, arg); break;
            }
            break;
        }
    }

    return 0;
}
