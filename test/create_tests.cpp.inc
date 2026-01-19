#include "mruby.h"
#include "mruby/compile.h"
#include <string>
#include <iostream>

#include "ossp/ossp.h"
#include "tl/expected.hpp"

#define ERR_ENDL(msg) std::cerr << msg << std::endl; return 1;
#define ERR(msg) std::cerr << msg;
#define FREE_MRB mrbc_context_free(state, context); mrb_close(state);

using namespace lyniat::ossp::serialize::bin;

const std::string test_file_name = "test.bin";

int load_code(mrb_state* state, mrbc_context* context, const std::string& str) {
    mrb_load_string_cxt(state, str.c_str(), context);

    if (state->exc) {
        mrb_print_error(state);
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
                                       char* meta_data = nullptr;
                                       mrb_get_args(state, "o|z", &data, &meta_data);
                                       if (meta_data != nullptr) {
                                           auto str_meta_data = std::string(meta_data);
                                           OSSP::Serialize(serialized_data, state, data, str_meta_data);
                                       } else {
                                           OSSP::Serialize(serialized_data, state, data);
                                       }
                                       return mrb_nil_value();
                                   }
                               }, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));

    mrb_define_module_function(state, module, "serialize_and_save", {
                               [](mrb_state* state, mrb_value self) {
                                   mrb_value data;
                                   char* meta_data = nullptr;
                                   mrb_get_args(state, "o|z", &data, &meta_data);
                                   if (meta_data != nullptr) {
                                       auto str_meta_data = std::string(meta_data);
                                       OSSP::Serialize(serialized_data, state, data, str_meta_data);
                                       auto test_path = std::filesystem::current_path().append(test_file_name);
                                       serialized_data->WriteToDisk(test_path);
                                   } else {
                                       OSSP::Serialize(serialized_data, state, data);
                                   }
                                   return mrb_nil_value();
                               }
                           }, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));

    if (state->exc) {
        mrb_print_error(state);
        mrbc_context_free(state, context);
        mrb_close(state);
        return 1;
    }

    mrb_define_module_function(state, module, "deserialize", {
                                   [](mrb_state* mrb, mrb_value self) {
                                       auto data = OSSP::Deserialize(serialized_data, mrb);
                                       if (data) {
                                           return data.value<>();
                                       }
                                       auto error = generate_OSSP_error_message(data.error());
                                       std::cout << error << std::endl;
                                       mrb_raise(mrb, E_RUNTIME_ERROR, error.c_str());
                                       // Return value is needed for OService build
                                       // ReSharper disable once CppDFAUnreachableCode
                                       return mrb_nil_value();
                                   }
                               }, MRB_ARGS_NONE());

    mrb_define_module_function(state, module, "load_and_deserialize", {
                               [](mrb_state* mrb, mrb_value self) {
                                   auto test_path = std::filesystem::current_path().append(test_file_name);
                                   serialized_data = new ByteBuffer(test_path);
                                   auto data = OSSP::Deserialize(serialized_data, mrb);
                                   if (data) {
                                          return data.value<>();
                                   }
                                   auto error = generate_OSSP_error_message(data.error());
                                   std::cout << error << std::endl;
                                   mrb_raise(mrb, E_RUNTIME_ERROR, error.c_str());
                                   // Return value is needed for OService build
                                   // ReSharper disable once CppDFAUnreachableCode
                                   return mrb_nil_value();
                               }
                           }, MRB_ARGS_NONE());

    if (state->exc) {
        mrb_print_error(state);
        mrbc_context_free(state, context);
        mrb_close(state);
        return 1;
    }

    return load_code(state, context, ruby_diff_method);
}