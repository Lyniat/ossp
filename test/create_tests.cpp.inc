#include "mruby.h"
#include "mruby/compile.h"
#include "ossp/serialize.h"
#include <string>

using namespace lyniat::ossp::serialize::bin;

int load_code(mrb_state* state, mrbc_context* context, const std::string& str) {
    mrb_load_string_cxt(state, str.c_str(), context);

    if (state->exc) {
        mrb_funcall(state, mrb_obj_value(state->exc), "inspect", 0);
        mrbc_context_free(state, context);
        mrb_close(state);
        return 1;
    }
    return 0;
}

int create_test_data(mrb_state* state, mrbc_context* context) {
    auto module = mrb_define_module_under(state, state->object_class, "OSSP");
    mrb_define_module_function(state, module, "serialize", {
                                   [](mrb_state* state, mrb_value self) {
                                       mrb_value data;
                                       mrb_get_args(state, "o", &data);
                                       start_serialize_data(serialized_data, state, data);
                                       return mrb_nil_value();
                                   }
                               }, MRB_ARGS_REQ(1));

    if (state->exc) {
        mrb_funcall(state, mrb_obj_value(state->exc), "inspect", 0);
        mrbc_context_free(state, context);
        mrb_close(state);
        return 1;
    }

    mrb_define_module_function(state, module, "deserialize", {
                                   [](mrb_state* state, mrb_value self) {
                                       auto data = start_deserialize_data(serialized_data, state);
                                       return data;
                                   }
                               }, MRB_ARGS_NONE());

    if (state->exc) {
        mrb_funcall(state, mrb_obj_value(state->exc), "inspect", 0);
        mrbc_context_free(state, context);
        mrb_close(state);
        return 1;
    }

    return load_code(state, context, ruby_diff_method);
}