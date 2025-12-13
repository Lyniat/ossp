#pragma once

#include <bytebuffer/buffer.h>
#include "../mruby.h"
#include "serialize.h"

namespace lyniat::ossp::serialize::bin {
using namespace lyniat::memory::buffer;
class OSSP {
public:
    OSSP() = delete;

    ~OSSP() = delete;

    static void Serialize(ByteBuffer* bb, mrb_state* mrb, mrb_value data, const std::string& meta_data = "");

    static mrb_value Deserialize(ByteBuffer* bb, mrb_state* mrb);

private:
    static void SerializeRecursive(ByteBuffer* bb, mrb_state* mrb, mrb_value data);

    static mrb_value DeserializeRecursive(ByteBuffer* bb, mrb_state* mrb);

    static bool SetHashKey(ByteBuffer* bb, mrb_state* state, mrb_value hash);

    static bool AddHashKey(ByteBuffer* bb, mrb_state* state, mrb_value key);

    static serialized_type GetType(mrb_value data);

    static serialized_type SplitInt64(int64_t value, ByteBuffer* bb);

    static serialized_type GetMinBytes(int64_t value);
};

}