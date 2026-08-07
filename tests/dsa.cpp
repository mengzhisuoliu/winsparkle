#include <gtest/gtest.h>

#include "signatureverifier.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>

using namespace winsparkle;

namespace Crypto
{

namespace
{

const char PublicKey2048[] = R"(-----BEGIN PUBLIC KEY-----
MIIDQjCCAjUGByqGSM44BAEwggIoAoIBAQCpUli1vUb6pb3vpa5uSzqrPNZGR7Ez
L3MKB9LQxvbwlXqK51953uW/2irHdJbtvcZ50OYhunONn4esPpOQXoCIM91EgsI9
bgW6Ha7dU+rdfJ3HK0ipbWHIbymNBKLWU3yVuBn+wanNPDll0EyrZceJ1OBMJgh0
5qS9uLiDJgBK8ZIylXJaCNYcOHE1oA/rVfLw2jlRZiUZTmFdJESzzafQKUbYNWo3
YPn2k5y1j+eBJ142Xof7pg1iFkXpdO0hLVRM1UxCMJgt6oRUs0vX6ULHFkvmO5+H
8C3/EoITx++BEWinF6narjv41ha2mAlxFK+ttCpXZ0xiUkV+WagwXffXAh0Am1lB
uDgxPvZ1c4D84LmG05Tkl11pjkjHgx3QaQKCAQAvFWi79bggvRO/8r2jiBD3M9QQ
6S2eaj5CnjPqBAmJ5HMvEkwpbKusE3XB2qERAEIYlWU9MFX35IoDIvdfnYRLeBDQ
pDI064OvwEl+1PZUuHGxJP5BoMYPmf684yg4QPtePyjcEA2SICafHA0AsUCDWznu
KazxcCdXnjACCJfzB9R89t+v+75WPlvWyPNlTzME9RJ4asnpatONsHtHUKo73I0K
PlX4tx6Iza9IZiw7Tqu0TdzWH1Ydd4NtK2S113skddskUl2HBlzsxkGZ4p2PF+gD
6r/JqLMTjT+/AZCnd5zK//tUIBLSN42WyHsmyLMHp7jGdpuuREdZLMf8yt9kA4IB
BQACggEAUQyqpLDVP6JiwL8w9h8awO9jV8oiR/8RPR/PPiSDxpGeCC9VWqrSUGgB
JkwvbNnzAgb8/To5K2DCbhsBqVkLXymg8rggu50+lKXpw5O/tpCbmSe9mog1j9iC
LdRuifLQMTlnjnW7dtsFNR9j9qOCXRfksVTgynTaDUm013LqvX1JAW0DScRM51If
Ywk5NjVTXL1PRn5vHohxZ+QOHnvSYhcb+m8n4a2lG7nFa2s8ON3l9rfHSJgN0d8S
KVGXhMCBINrSbdt+LCsg/qjPI6WyVv42rn3R4rjar3bzkrtUJJWR0S9n8fDHVQe7
j8zYfuQPzNg6GFy1TkUDJ+rspV73xw==
-----END PUBLIC KEY-----
)";

const char PublicKey3072[] = R"(-----BEGIN PUBLIC KEY-----
MIIEwzCCAzYGByqGSM44BAEwggMpAoIBgQCd/dbj+Cc3ECHiCag+cKLUQ8cIzKPV
ETOqzfVcv11K/LM4DmQqx1Lc/E2Po2s/+/3gByv4V6GwLXEcncFMA0p8Wdvomqau
AHzNJsnaBh8oI6TWj4aB3xEw/tHJFPGr3Vf+K3pjFiFz4T+0lS/EW0aKTKQz+7to
QLulDj7n33hV6y9wXwzOBt8Ej55biXUPa/+s6G8Ewe/DEqEp39lN/q72bOwZC2hA
6Cs2AS8kpnKVA3//cZofR4AJWIyGF7gF9A2mQhiavG8uF7iU9FmBMVfZo9ye7KQ2
ucz7z92LGksFeP9hw+sNq18mMJqsM4jjgZpugAUQyY/2kMz5wqxy0xNUAWINkt3l
gasUOvihRU/aPX1KZCPN/BivdXoyAgvpB17Sy47m4DKraFB+JEbJMCOn5RVcLI+Q
us6k2fSDMZ9iXopQj/U6/UNfVwQBR8yOIky4+5mikcEnhJptCf9GZTVo2cVTuacl
Lia53McW4o4/QKU/y6c2uZzciO05THRAOWUCHQDk2/IVbcqrC1MrQHKdOrYpwIg0
go4yfWRJhz/LAoIBgQCEelIaz1/A8kq3lPlljBBP/KI1k80MLvdwvFfvnHFc5ar8
unGwn52LZfguZ+3IW3qyTs2OOPpcw+ysblWNHbioUBPbPGtlJn5CbT46p0vWarhb
xF96XqaqJUdKRhaPh1LBVQP3mJRslSeBT8k9XqdaaON/l7jwjhC6BQ+2/2iSGSZy
0WmqarkOVpIDaTF7/FXNswD6ADtIQYFOR7LFkIOF5Tiv9zZl+hJUXdw2XsSFj/KS
7X9oIsoL3ftYMrRB9lthrOqJPwJ51GcDa0PBXwdIDuQ0y5vvnVIuKLuA6XKDLlLc
0vSH2RoqNrtTKz0M8AZw1+bRcFaZK2uqy86HhzjfXpXmBrN6HuGdtEBttI/zXvib
aqR6O3yo0D9dPhNIXrrPrXlx9mIlMcjgoVmbDgktWqYZgAfGXxdopIth/M2LJpRS
twioJ9fVYx4xrVJxEGGoQAHp1lUb4IrKkhR0bg0MgtJGpqqFcVaxW/a79kgEf/df
1Z/X0hVY8YcElNfKmeEDggGFAAKCAYBe27ac+LguzfDxXuFcuZdv6YIgU+JKn8uO
SfzPczDkgeFshj+RtBsSj61/xpj4yhCyRl69G2FXw7uw60rDMF0Td2xRgN4iGONq
5K+wYSau+t1/8vv5t/APG5Ehn27q74+PYCiNYEaz1QwO675qN9fUlvz5ZvvcVydK
uN9AXSB7XHrKjKH9Bz8qA1cBhyqnXar13BxYBCl3wFMuE1IPpwwnepBMchvswWyW
0orP/g6wWDefBDkQYezJyLBF3DvulHj4CLIolObhJ7tZY2RB9T9xikIns0errdSJ
vzeeC+F0FRaekjli4xSN3ailbXAraSnLPBpilm0+SmLojHq3BC56YeyW9n7N+sLI
Ex1E4zeugE71QfhQClq3E1DmbNTdX/fxnf/NT7JaXaMjQcEFjtNHflHsiQg7Dr7E
5dPmhyvpJxNM6dPM8aSQ8P1ultRHrp3mpUqHIPCjenaTSU709hvXR7O17AdRXqOY
nbSRf1m3/q5BrvIbH7dvqmV3ShyabbQ=
-----END PUBLIC KEY-----
)";

const char PublicKey4096[] = R"(-----BEGIN PUBLIC KEY-----
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
PjY4KG48Jt7SRAc9uvNS44JfyetFCS4=
-----END PUBLIC KEY-----
)";

struct TestVector
{
    const char *name;
    const char *publicKey;
    const char *payload1Signature;
    const char *emptyPayloadSignature;
};

const TestVector TestVectors[] =
{
    {
        "2048-bit",
        PublicKey2048,
        "MD0CHA/vqU2IV2dj0D+3HJa7jmIMI37T/p6kONVs/gUCHQCUFsBdXoCQFTL0ovuISVcymQseCD+mcfQjqDQc",
        "MD0CHG3B94g+zoTk+VSlJ5RJroYvVXMW2CVtjemFWDQCHQCJeN11U0VF8ZlGo8qw1RSOJvqPnDyyuXjsSOpv"
    },
    {
        "3072-bit",
        PublicKey3072,
        "MD0CHQCz6cmLdw6J24XdV0dn969MS/Eb01bZWlGQmdzSAhxa/G0zdmu30zvIinqX8bdxmyDh/zBi9nGm6epY",
        "MD4CHQCdG09xHzMyAlNjvVuqGs3Q5ioBGFBRFHNJMjuDAh0AyeIZReEy373iB+h87fg5Mh1bWhketwWTXnyx6A=="
    },
    {
        "4096-bit",
        PublicKey4096,
        "MDwCHGc444s/tKHukRYxf/PpNkAcziq05psRp7gsLecCHDciYjnxeBzRdAIh9f9CRo+v3eVo1WvybYPipYI=",
        "MDwCHEudmqB2rlmRyhXmSBXdXm112dJC8SH70XUZABQCHDoirSraZmMJzRr1PCz1SW86H2rrA87Oj8h9gjU="
    }
};

std::wstring TestFile(const wchar_t *name)
{
    wchar_t modulePath[MAX_PATH];
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length == 0 || length == MAX_PATH)
        throw std::runtime_error("Failed to determine test executable path");

    std::wstring path(modulePath, length);
    path.resize(path.find_last_of(L"\\/") + 1);
    path += name;
    return path;
}

} // anonymous namespace

TEST(DSA, ValidSignature)
{
    for (const auto& test : TestVectors)
    {
        SCOPED_TRACE(test.name);
        EXPECT_TRUE(SignatureVerifier::IsDSASHA1SignatureValid(
            test.publicKey, test.payload1Signature, TestFile(L"payload1.bin")));
    }
}

TEST(DSA, InvalidSignature)
{
    for (const auto& test : TestVectors)
    {
        SCOPED_TRACE(test.name);
        EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
            test.publicKey, test.payload1Signature, TestFile(L"payload2.bin")));
    }
}

TEST(DSA, EmptyFile)
{
    for (const auto& test : TestVectors)
    {
        SCOPED_TRACE(test.name);
        EXPECT_TRUE(SignatureVerifier::IsDSASHA1SignatureValid(
            test.publicKey, test.emptyPayloadSignature, TestFile(L"payload-empty.bin")));
        EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
            test.publicKey, test.payload1Signature, TestFile(L"payload-empty.bin")));
    }
}

TEST(DSA, NonExistentFile)
{
    for (const auto& test : TestVectors)
    {
        SCOPED_TRACE(test.name);
        EXPECT_ANY_THROW(SignatureVerifier::IsDSASHA1SignatureValid(
            test.publicKey, test.payload1Signature, TestFile(L"non-existent.bin")));
    }
}

TEST(DSA, RejectsEmptySignature)
{
    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        PublicKey2048, "", reinterpret_cast<const uint8_t*>("payload"), sizeof("payload") - 1));
}

TEST(DSA, RejectsTruncatedSignature)
{
    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        PublicKey2048,
        "MD0CHA/vqU2IV2dj0D+3HJa7jmIMI37T/p6kONVs/gUCHQCUFsBdXoCQFTL0ovuISVcymQseCD+mcfQjqDQ=",
        reinterpret_cast<const uint8_t*>("payload"), sizeof("payload") - 1));
}

TEST(DSA, RejectsSignatureWithTrailingGarbage)
{
    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        PublicKey2048,
        "MD0CHA/vqU2IV2dj0D+3HJa7jmIMI37T/p6kONVs/gUCHQCUFsBdXoCQFTL0ovuISVcymQseCD+mcfQjqDQcAA==",
        reinterpret_cast<const uint8_t*>("payload"), sizeof("payload") - 1));
}


namespace
{

constexpr char kPayload[] = "Malformed signature parser test payload.\n\n";
constexpr size_t kMaxBase64SignatureSize = 1000;

constexpr char kPublicKey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBtjCCASsGByqGSM44BAEwggEeAoGBAKU8/avmkFeGnSqwYG7dZnQlG+01QNax\n"
    "u3F5v0NcL/SRUW7IdpUq8t14siK0mA6yjphLhOf5t8gugTEVBllP86ANSbFigH7W\n"
    "N3v6ydJWqm60pNhNHN//50cnNtIsXbxeq3VtsI64pkH1OJqeZDHLmu73k4T0EKOz\n"
    "sylSfF/wtVBJAhUAoabmyx1YsDwfo0r1G/HuEx0uzwUCgYAJD1PMCiTCQa1xyD/N\n"
    "CWOajCufTOIzKAhm6l+nlBVPiKI+262XpYt127Ke4mPL8XJBizoTjSQN08uHMg/8\n"
    "L6W/cdO2aZ+mhkBnS1xAm83DAwqLrDraR1w/4QRFxr5Vbyy8qnejrPjTJobBN1BG\n"
    "sv84wHkjmoCn6pFIfkGYeATlJgOBhAACgYAHYPU1zMVBTDWru7SNC4G2UyWGWYYL\n"
    "jLytBVHfQmBa51CmqrSs2kCfGLGA1ynfYENsxcJq9nsXrb4i17H5BHJFkH0g7BUD\n"
    "peBeLr8gsK3WgfqWwtZsDkltObw9chUD/siK6q/dk/fSIB2Ho0inev7k68Z5ZkNI\n"
    "4XOwuEssAVhmwA==\n"
    "-----END PUBLIC KEY-----\n";

void ExpectMalformedDerRejected(const char* signature)
{
    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        kPublicKey, signature, reinterpret_cast<const uint8_t*>(kPayload),
        sizeof(kPayload) - 1));
}

void AppendDerLength(std::vector<unsigned char>* output, size_t length)
{
    if (length < 0x80)
    {
        output->push_back(static_cast<unsigned char>(length));
        return;
    }

    unsigned char bytes[sizeof(length)];
    size_t count = 0;
    while (length != 0)
    {
        bytes[count++] = static_cast<unsigned char>(length & 0xFF);
        length >>= 8;
    }

    output->push_back(static_cast<unsigned char>(0x80 | count));
    while (count != 0)
        output->push_back(bytes[--count]);
}

void AppendInteger(std::vector<unsigned char>* output, size_t size)
{
    output->push_back(0x02);
    AppendDerLength(output, size);
    output->insert(output->end(), size, 0xFF);
}

std::string Base64Encode(const std::vector<unsigned char>& input)
{
    constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    for (size_t i = 0; i < input.size(); i += 3)
    {
        uint32_t chunk = static_cast<uint32_t>(input[i]) << 16;
        if (i + 1 < input.size())
            chunk |= static_cast<uint32_t>(input[i + 1]) << 8;
        if (i + 2 < input.size())
            chunk |= input[i + 2];

        output.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        output.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        output.push_back(i + 1 < input.size() ? kAlphabet[(chunk >> 6) & 0x3F] : '=');
        output.push_back(i + 2 < input.size() ? kAlphabet[chunk & 0x3F] : '=');
    }

    return output;
}

std::string MakeLargeSignature(size_t integer_size)
{
    std::vector<unsigned char> contents;
    AppendInteger(&contents, integer_size);
    AppendInteger(&contents, integer_size);

    std::vector<unsigned char> der;
    der.push_back(0x30);
    AppendDerLength(&der, contents.size());
    der.insert(der.end(), contents.begin(), contents.end());
    return Base64Encode(der);
}

}  // namespace

TEST(DSA, RejectsNonAsciiInput)
{
    // Non-ASCII input that must be rejected by the Base64 decoder.
    const char signature[] = "\xC3\xA9\n\n";

    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        kPublicKey, signature, reinterpret_cast<const uint8_t*>(kPayload),
        sizeof(kPayload) - 1));
}

TEST(DSA, RejectsSequenceTagWithoutLength)
{
    // A SEQUENCE tag without a length byte.
    const char signature[] = "MA==\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsLongFormLengthWithoutLengthByte)
{
    // A one-byte long-form length without its length byte.
    const char signature[] = "MIE=\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsEightMissingLengthBytes)
{
    // A long-form length claiming eight missing length bytes.
    const char signature[] = "MIg=\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsEmptySequence)
{
    // An empty SEQUENCE.
    const char signature[] = "MAA=\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsIntegerTagWithoutLength)
{
    // An INTEGER tag without a length byte.
    const char signature[] = "MAEC\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsIntegerWithMissingLongFormLengthByte)
{
    // An INTEGER with a missing long-form length byte.
    const char signature[] = "MAICgQ==\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsMissingSInteger)
{
    // A complete r followed by a missing s.
    const char signature[] = "MAMCAQE=\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsSIntegerWithoutLength)
{
    // A complete r and an s with a missing length byte.
    const char signature[] = "MAYCAQECgQ==\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsContentLargerThanInput)
{
    // A SEQUENCE whose declared content is larger than the input.
    const char signature[] = "MIL//w==\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsLengthClaiming127MissingBytes)
{
    // A length-of-length value claiming 127 missing bytes.
    const char signature[] = "MP8=\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, RejectsLengthThatWrapsPointerArithmetic)
{
    // An in-bounds SEQUENCE containing an INTEGER whose SIZE_MAX length wraps
    // the `der + length` bounds check before mp_read_unsigned_bin is called.
    const char signature[] = "MAoCiP//////////\n\n";
    ExpectMalformedDerRejected(signature);
}

TEST(DSA, SignatureWithinLimitCompletesPromptly)
{
    const std::string signature = MakeLargeSignature(367);
    ASSERT_EQ(996U, signature.size());
    ASSERT_LT(signature.size(), kMaxBase64SignatureSize);

    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(SignatureVerifier::IsDSASHA1SignatureValid(
        kPublicKey, signature.c_str(), reinterpret_cast<const uint8_t*>(kPayload),
        sizeof(kPayload) - 1));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(1));
}

TEST(DSA, OversizedSignatureIsRejectedWithoutUnboundedWork)
{
    const std::string signature = MakeLargeSignature(512 * 1024);
    ASSERT_GT(signature.size(), kMaxBase64SignatureSize);

    EXPECT_EXIT(
        {
            std::thread([]
            {
                Sleep(3000);
                ExitProcess(EXIT_FAILURE);
            }).detach();
            ExitProcess(SignatureVerifier::IsDSASHA1SignatureValid(
                kPublicKey, signature.c_str(), reinterpret_cast<const uint8_t*>(kPayload),
                sizeof(kPayload) - 1) ? EXIT_FAILURE : EXIT_SUCCESS);
        },
        testing::ExitedWithCode(EXIT_SUCCESS), "");
}

} // namespace Crypto
