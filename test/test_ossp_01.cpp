#include "mruby/compile.h"
#include "ossp/help.h"
#include "ossp/serialize.h"

ByteBuffer* serialized_data;

#include "test_data.cpp.inc"
#include "create_tests.cpp.inc"

using namespace lyniat::ossp::serialize::bin;

int main() {
    serialized_data = new ByteBuffer();

    auto state = mrb_open();
    auto context = mrbc_context_new(state);

    auto result = create_test_data(state, context);
    if (result != 0) {
        delete serialized_data;
        return result;
    }

    load_code(state, context, ruby_test_string);
    load_code(state, context, ruby_code);

    auto test_result = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_result", 0);
    auto test_int = static_cast<int>(mrb_integer(test_result));

    mrbc_context_free(state, context);
    mrb_close(state);

    delete serialized_data;
    return test_int;
}