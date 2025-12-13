#include "ossp/ossp.h"

namespace lyniat::ossp::serialize::bin {
void start_serialize_data(ByteBuffer* bb, mrb_state* mrb, mrb_value data) {
    OSSP::Serialize(bb, mrb, data);
}

mrb_value start_deserialize_data(ByteBuffer* bb, mrb_state* mrb) {
    return OSSP::Deserialize(bb, mrb);
}
}