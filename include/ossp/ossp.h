#pragma once

#include <bytebuffer/ByteBuffer.h>
#include <sstream>
#include "../mruby.h"
#include "serialize.h"

#include "tl/expected.hpp"

namespace lyniat::ossp::serialize::bin {
using namespace lyniat::memory::buffer;

static constexpr Endianness endian = Big;

enum class OSSPErrorType : uint8_t {
    InvalidType = 0,
    ReadingError,
    MissingMagicNumber,
    MissingEOD,
    MissingEOF,
    WrongBufferSize
};

struct OSSPErrorInfo {
    OSSPErrorType type;
    std::string message;
    size_t position;
};

const OSSPErrorInfo OSSPErrorInfoInvalidType =
    {OSSPErrorType::InvalidType, "Invalid mRuby type.", 0};

const OSSPErrorInfo OSSPReadingError =
    {OSSPErrorType::ReadingError, "Error reading OSSP.", 0};

const OSSPErrorInfo OSSPMagicNumberError =
{OSSPErrorType::MissingMagicNumber, "Missing magic number.", 0};

const OSSPErrorInfo OSSPEODError =
{OSSPErrorType::MissingEOD, "Missing EOD.", 0};

const OSSPErrorInfo OSSPEOFError =
{OSSPErrorType::MissingEOF, "Missing EOF.", 0};

const OSSPErrorInfo OSSPWrongBufferSizeError =
{OSSPErrorType::WrongBufferSize, "Wrong buffer size.", 0};

inline std::string generate_OSSP_error_message(const OSSPErrorInfo& info) {
    std::stringstream ss;
    ss <<"Error 0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (uint64_t)info.type
    << ": " << info.message << " (0x" << std::setw(8) << info.position << ")";
    return ss.str();
}

class OSSP {
public:
    OSSP() = delete;

    ~OSSP() = delete;

    static void Serialize(ByteBuffer* bb, mrb_state* mrb, mrb_value data, const std::string& meta_data = "");

    static tl::expected<mrb_value, OSSPErrorInfo> Deserialize(ReadBuffer* bb, mrb_state* mrb);

private:
    static void SerializeRecursive(ByteBuffer* bb, mrb_state* mrb, mrb_value data);

    static tl::expected<mrb_value, OSSPErrorInfo> DeserializeRecursive(ReadBuffer* rb, mrb_state* mrb);

    static tl::expected<mrb_value, OSSPErrorInfo> SetHashKey(ReadBuffer* rb, mrb_state* state, mrb_value hash);

    static tl::expected<mrb_value, OSSPErrorInfo> AddHashKey(ByteBuffer* bb, mrb_state* state, mrb_value key);

    static serialized_type GetType(mrb_value data);

    static serialized_type SplitInt64(int64_t value, ByteBuffer* bb);

    static serialized_type GetMinBytes(int64_t value);
};

}