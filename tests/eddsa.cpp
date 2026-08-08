
#include <gtest/gtest.h>

#include "signatureverifier.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "wrapwin.h"

using namespace winsparkle;


namespace Crypto
{

namespace
{

const char PublicKey[] = "G67rL6eZhgVbnl1nnphlrq7M3RuVXvaxqTqEexPcYAE=";

const char Payload1Signature[] =
    "hK57iDPc5XJMtPRRYu+P8hYeXzFU3cduE18jhYVkHkEm7jlkcxJo2/eoQoFe6ZJr"
    "xPDEBTIKoysMe5I5eQXmCg==";

const char EmptyPayloadSignature[] =
    "I/HmOs8NsFpNs0YWgPRaTb/xGy1/K6/xDpk1OtD83Q1qXDeaUDqMqAbWuk2OtA+6"
    "XaD5IybHMJNMne+XrfNMBg==";

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

TEST(EdDSA, ValidSignature)
{
    EXPECT_TRUE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, Payload1Signature, TestFile(L"payload1.bin")));
}

TEST(EdDSA, InvalidSignature)
{
    EXPECT_FALSE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, Payload1Signature, TestFile(L"payload2.bin")));
}

TEST(EdDSA, EmptyFile)
{
    EXPECT_TRUE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, EmptyPayloadSignature, TestFile(L"payload-empty.bin")));
    EXPECT_FALSE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, Payload1Signature, TestFile(L"payload-empty.bin")));
}

TEST(EdDSA, NonExistentFile)
{
    EXPECT_ANY_THROW(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, Payload1Signature, TestFile(L"non-existent.bin")));
}

TEST(EdDSA, RFC8032Vector1)
{
    const uint8_t payload = 0;
    EXPECT_TRUE(SignatureVerifier::IsEdDSASignatureValid(
        "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==",
        &payload, 0));
}

TEST(EdDSA, RFC8032Vector2)
{
    const uint8_t payload[] = { 0x72 };
    EXPECT_TRUE(SignatureVerifier::IsEdDSASignatureValid(
        "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=",
        "kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA==",
        payload, sizeof(payload)));
}

TEST(EdDSA, RFC8032Vector3)
{
    const uint8_t payload[] = { 0xaf, 0x82 };
    EXPECT_TRUE(SignatureVerifier::IsEdDSASignatureValid(
        "/FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU=",
        "YpHWV97sJAJIJ+acOr4BowzlSKKEdDpEXjaA19taw6wY/5tTjRbykK5n92CYTcZZSnwV6XFu0o3AJ77O6h7ECg==",
        payload, sizeof(payload)));
}

TEST(EdDSA, RejectsEmptySignature)
{
    const uint8_t payload = 0;
    EXPECT_FALSE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey, "", &payload, 1));
}

TEST(EdDSA, RejectsTruncatedSignature)
{
    const uint8_t payload = 0;
    EXPECT_FALSE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey,
        "hK57iDPc5XJMtPRRYu+P8hYeXzFU3cduE18jhYVkHkEm7jlkcxJo2/eoQoFe6ZJrxPDEBTIKoysMe5I5eQXm",
        &payload, 1));
}

TEST(EdDSA, RejectsSignatureWithTrailingGarbage)
{
    const uint8_t payload = 0;
    EXPECT_FALSE(SignatureVerifier::IsEdDSASignatureValid(
        PublicKey,
        "hK57iDPc5XJMtPRRYu+P8hYeXzFU3cduE18jhYVkHkEm7jlkcxJo2/eoQoFe6ZJrxPDEBTIKoysMe5I5eQXmCgA=",
        &payload, 1));
}

} // namespace Crypto
