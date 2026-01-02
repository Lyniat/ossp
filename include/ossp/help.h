/*
* MIT License
*
* Copyright (c) 2025 Laurin "lyniat" Muth
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
*         of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
*         to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*         copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
*         copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*         AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#pragma once

#include "api.h"
#include <string>

#define CEXT_INT(mrb,i) drb_api->mrb_int_value(mrb,i)

#define STRINGIFY(x) STRINGIFY_IMPL(x)
#define STRINGIFY_IMPL(x) #x

#ifdef USE_DRGTK
#define mrb_hash_set API->mrb_hash_set
#define mrb_hash_get API->mrb_hash_get
#define mrb_hash_new API->mrb_hash_new
#define mrb_hash_foreach API->mrb_hash_foreach
#define mrb_str_new_cstr API->mrb_str_new_cstr
#define mrb_str_to_cstr API->mrb_str_to_cstr
#define mrb_int_value API->mrb_int_value
#define mrb_float_value API->mrb_float_value
#define mrb_sym_name API->mrb_sym_name
#define mrb_hash_new_capa API->mrb_hash_new_capa
#define mrb_string_cstr API->mrb_string_cstr
#define mrb_obj_to_sym API->mrb_obj_to_sym
#define mrb_str_new API->mrb_str_new
#define mrb_to_flo API->mrb_to_flo
#define mrb_to_int API->mrb_to_int
#define mrb_intern_check_cstr API->mrb_intern_check_cstr
#define mrb_intern_cstr API->mrb_intern_cstr
#define mrb_intern_str API->mrb_intern_str
#define mrb_symbol_value API->mrb_symbol_value
#define mrb_ary_new_capa API->mrb_ary_new_capa
#define mrb_ary_set API->mrb_ary_set
#define mrb_malloc API->mrb_malloc
#define mrb_calloc API->mrb_calloc
#define mrb_free API->mrb_free
#define mrb_funcall API->mrb_funcall
#define mrb_define_module_function API->mrb_define_module_function
#define mrb_get_args API->mrb_get_args
#define mrb_module_get API->mrb_module_get
#define mrb_class_get API->mrb_class_get
#define mrb_class_get_under API->mrb_class_get_under
#define mrb_load_string API->mrb_load_string
#define mrb_class_path API->mrb_class_path
#define mrb_close API->mrb_close
#define mrbc_context_free API->mrbc_context_free
#define mrb_raise API->mrb_raise
#define mrb_open API->mrb_open
#define mrbc_context_new API->mrbc_context_new
#define mrb_define_module_under API->mrb_define_module_under
#define mrb_load_string_cxt API->mrb_load_string_cxt
#define mrb_obj_value API->mrb_obj_value
#define mrb_exc_get_id API->mrb_exc_get_id
#define mrb_hash_size API->mrb_hash_size
#define mrb_intern_static API->mrb_intern_static
#define mrb_obj_new API->mrb_obj_new
#define mrb_class_new_instance API->mrb_class_new_instance
#else
#define mrb_hash_set mrb_hash_set
#define mrb_hash_get mrb_hash_get
#define mrb_hash_new mrb_hash_new
#define mrb_hash_foreach mrb_hash_foreach
#define mrb_str_new_cstr mrb_str_new_cstr
#define mrb_str_to_cstr mrb_str_to_cstr
#define mrb_int_value mrb_int_value
#define mrb_float_value mrb_float_value
#define mrb_sym_name mrb_sym_name
#define mrb_hash_new_capa mrb_hash_new_capa
#define mrb_string_cstr mrb_string_cstr
#define mrb_obj_to_sym mrb_obj_to_sym
#define mrb_str_new mrb_str_new
#define mrb_to_flo mrb_to_flo
#define mrb_to_int mrb_to_int
#define mrb_intern_check_cstr mrb_intern_check_cstr
#define mrb_intern_cstr mrb_intern_cstr
#define mrb_intern_str mrb_intern_str
#define mrb_symbol_value mrb_symbol_value
#define mrb_ary_new_capa mrb_ary_new_capa
#define mrb_ary_set mrb_ary_set
#define mrb_malloc mrb_malloc
#define mrb_calloc mrb_calloc
#define mrb_free mrb_free
#define mrb_funcall mrb_funcall
#define mrb_define_module_function mrb_define_module_function
#define mrb_get_args mrb_get_args
#define mrb_module_get mrb_module_get
#define mrb_class_get mrb_class_get
#define mrb_class_get_under mrb_class_get_under
#define mrb_load_string mrb_load_string
#define mrb_class_path mrb_class_path
#define mrb_close mrb_close
#define mrbc_context_free mrbc_context_free
#define mrb_raise mrb_raise
#define mrb_open mrb_open
#define mrbc_context_new mrbc_context_new
#define mrb_define_module_under mrb_define_module_under
#define mrb_load_string_cxt mrb_load_string_cxt
#define mrb_obj_value mrb_obj_value
#define mrb_exc_get_id mrb_exc_get_id
#define mrb_hash_size mrb_hash_size
#define mrb_intern_static mrb_intern_static
#define mrb_obj_new mrb_obj_new
#define mrb_class_new_instance mrb_class_new_instance
#endif

mrb_int cext_to_int(mrb_state* mrb, mrb_value value);

mrb_float cext_to_float(mrb_state* mrb, mrb_value value);

const char* cext_to_string(mrb_state* mrb, mrb_value value);

mrb_sym cext_sym(mrb_state* mrb, const char* str);

mrb_value cext_key(mrb_state* mrb, const char* str);

mrb_value cext_hash_get(mrb_state* mrb, mrb_value hash, const char* key);

mrb_int cext_hash_get_int(mrb_state* mrb, mrb_value hash, const char* key);

const char* cext_hash_get_string(mrb_state* mrb, mrb_value hash, const char* key);

mrb_sym cext_hash_get_sym(mrb_state* mrb, mrb_value hash, const char* key);

mrb_value cext_hash_get_save_hash(mrb_state* mrb, mrb_value hash, const char* key);

void cext_hash_set_kstr(mrb_state* mrb, mrb_value hash, const char* key, mrb_value val);

void cext_hash_set_ksym(mrb_state* mrb, mrb_value hash, const char* key, mrb_value val);

bool cext_is_string(mrb_state* mrb, mrb_value value);

bool cext_is_symbol(mrb_state* mrb, mrb_value value);

bool cext_is_int(mrb_state* mrb, mrb_value value);

bool cext_is_hash(mrb_state* mrb, mrb_value value);

bool cext_is_array(mrb_state* mrb, mrb_value value);

bool cext_is_undef(mrb_state* mrb, mrb_value value);

bool cext_is_valid_type(mrb_state* mrb, mrb_value value);

mrb_int cext_hash_get_int_default(mrb_state* mrb, mrb_value hash, const char* key, mrb_int def);

const char* cext_hash_get_string_default(mrb_state* mrb, mrb_value hash, const char* key, const char* def);

mrb_sym cext_hash_get_sym_default(mrb_state* mrb, mrb_value hash, const char* key, mrb_sym def);


#define PEXT_H(HASH, KEY, VAL) pext_hash_set(__temp_state, HASH, KEY, VAL)

#define SKEY(KEY) mrb_symbol_value(KEY)

//HASH sym
inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, mrb_value val) {
    mrb_hash_set(state, hash, SKEY(key), val);
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, mrb_int val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_int_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, const int val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_int_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, mrb_float val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_float_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, const char* val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_str_new_cstr(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, const std::string& val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_str_new_cstr(state, val.c_str()));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, const bool val) {
    mrb_hash_set(state, hash, SKEY(key), mrb_bool_value(val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, mrb_sym key, mrb_sym val) {
    mrb_hash_set(state, hash, SKEY(key), SKEY(val));
}

// HASH string
inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, mrb_value val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), val);
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, mrb_int val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_int_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, const int val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_int_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, mrb_float val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_float_value(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, const char* val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_str_new_cstr(state, val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, const std::string& val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_str_new_cstr(state, val.c_str()));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, const bool val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), mrb_bool_value(val));
}

inline void pext_hash_set(mrb_state* state, mrb_value hash, const char* key, mrb_sym val) {
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), SKEY(val));
}

#undef SKEY

mrb_sym pext_sym(mrb_state* state, const char* str);

mrb_sym pext_sym(mrb_state* state, const std::string& val);

mrb_value pext_sym_val(mrb_state* state, const char* str);

mrb_value pext_sym_val(mrb_state* state, const std::string& val);

mrb_value pext_str(mrb_state* state, const char* str);

mrb_value pext_str(mrb_state* state, const std::string& str);