#include "mruby/compile.h"
#include "ossp/help.h"
#include "ossp/serialize.h"

ByteBuffer* serialized_data;

#include "test_data.cpp.inc"
#include "create_tests.cpp.inc"

#include "test_data_04.cpp.inc"

using namespace lyniat::ossp::serialize::bin;

const std::string expected_result = R"([{:path=>[:random_string_in_between], :a=>false, :b=>"--"}, {:path=>["dev_info", :age], :a=>256.3, :b=>256}, {:path=>[:different_keys, 3.14], :a=>:PI, :b=>"PI"}])";

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
    load_code(state, context, ruby_test_string_04);
    load_code(state, context, ruby_code_04);

    auto test_diff = mrb_funcall(state, mrb_obj_value(state->exc), "get_test_diff", 0);
    auto test_str = std::string(mrb_string_cstr(state, test_diff));

    mrbc_context_free(state, context);
    mrb_close(state);

    delete serialized_data;

    if (test_str != expected_result) {
        return 1;
    }

    return 0;
}