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
    load_code(state, context, ruby_code_serialize);

    auto test_path = std::filesystem::current_path().append(test_file_name);
    auto hash = serialized_data->Hash();
    if (!serialized_data->WriteToDisk(test_path)) {
        return 1;
    }

    auto read_data = new ByteBuffer(test_path);
    if (read_data->Size() == 0) {
        return 1;
    }
    auto read_hash = read_data->Hash();

    if (hash != read_hash) {
        return 1;
    }

    delete serialized_data;
    serialized_data = read_data;

    load_code(state, context, ruby_code_deserialize);
    load_code(state, context, ruby_code_diff);

    auto test_size_diff = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_size_diff", 0);
    auto test_int = static_cast<int>(mrb_integer(test_size_diff));

    auto test_result = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_meta", 0);
    if (!mrb_nil_p(test_result)) {
        mrbc_context_free(state, context);
        mrb_close(state);
        delete serialized_data;
        return 1;
    }

    mrbc_context_free(state, context);
    mrb_close(state);

    delete serialized_data;
    return test_int;
}