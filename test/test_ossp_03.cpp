#include "mruby/compile.h"
#include "ossp/help.h"
#include "ossp/serialize.h"

ByteBuffer* serialized_data;

#include "test_data.cpp.inc"
#include "create_tests.cpp.inc"

#include "test_data_03.cpp.inc"

using namespace lyniat::ossp::serialize::bin;

const std::string expected_result = R"([{:path=>["more_numbers"], :a=>[0, 22], :b=>:__missing__}])";

int main() {
    serialized_data = new ByteBuffer();

    auto state = mrb_open();
    auto context = mrbc_context_new(state);

    auto result = create_test_data(state, context);
    if (result != 0) {
        mrbc_context_free(state, context);
        mrb_close(state);
        delete serialized_data;
        return result;
    }

    load_code(state, context, ruby_test_string);
    load_code(state, context, ruby_test_string_03);
    load_code(state, context, ruby_code_03);

    auto test_size_diff = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_size_diff", 0);
    auto test_int = static_cast<int>(mrb_integer(test_size_diff));
    if (test_int == 0) {
        mrbc_context_free(state, context);
        mrb_close(state);
        delete serialized_data;
        return 1;
    }

    auto test_diff = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_diff", 0);
    auto test_str = std::string(mrb_string_cstr(state, test_diff));

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

    if (test_str != expected_result) {
        return 1;
    }

    return 0;
}