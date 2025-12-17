#include <string>

const std::string ruby_diff_method = R"(
def deep_diff(a, b, path = [])
    # Check for same class
    return [{ path: path, a: a, b: b }] unless a.class == b.class

    # Hash
    if a.is_a?(Hash) && b.is_a?(Hash)
        diffs = []

        keys = {}
        a.each_key { |k| keys[k] = true }
        b.each_key { |k| keys[k] = true }

        keys.each_key do |k|
            if !a.has_key?(k)
                diffs << { path: path + [k], a: :__missing__, b: b[k] }
            elsif !b.has_key?(k)
                diffs << { path: path + [k], a: a[k], b: :__missing__ }
            else
                diffs.concat deep_diff(a[k], b[k], path + [k])
            end
        end
        return diffs
    end

    # Array
    if a.is_a?(Array) && b.is_a?(Array)
        diffs = []
        max = a.size > b.size ? a.size : b.size
        i = 0
        while i < max
            va = i < a.size ? a[i] : :__missing__
            vb = i < b.size ? b[i] : :__missing__
            diffs.concat deep_diff(va, vb, path + [i])
            i += 1
        end
        return diffs
    end

    # Primitives
    if a == b
        []
    else
        [{ path: path, a: a, b: b }]
    end
end

def get_test_meta
    return $result_meta
end

def get_test_diff
    return $test_diff.to_s
end

def get_test_size_diff
    return $test_diff.size
end
)";

const std::string ruby_test_string = R"(
$test_data = {
    "this_is_data?" => true,
    :letters => [
        "a",
        "b",
        "c",
        "d",
    ],
    "numbers" => [
        [1, 1.1],
        [2, 2.2],
        [-3, -3.3],
    ],
    "random_string_in_between": "--",
    "dev_info" => {
        "gender" => "raccoon",
        :age => 256,
        "name" => "lyniat",
        "knows_how_to_code" => true,
        "knows_how_to_code_good" => false,
        :credit_card => {
            "type" => "Coders Club",
            "card number" => "0016 0032 0064 0128",
        },
    },
    "what_causes_exceptions?": nil,
    "different_keys": {
        567 => "567",
        "abc" => "ABC",
        3.14 => "PI",
    },
    "end_of_data" => true,
}
)";

const std::string ruby_code = R"(
OSSP.serialize($test_data)
$result, $result_meta = OSSP.deserialize()
$test_diff = deep_diff($test_data, $result)
)";

const std::string ruby_code_serialize = R"(
OSSP.serialize($test_data)
)";

const std::string ruby_code_deserialize = R"(
$result, $result_meta = OSSP.deserialize()
)";

const std::string ruby_code_serialize_and_save = R"(
OSSP.serialize_and_save($test_data)
)";

const std::string ruby_code_load_and_deserialize = R"(
$result, $result_meta = OSSP.load_and_deserialize()
)";

const std::string ruby_code_diff = R"(
$test_diff = deep_diff($test_data, $result)
)";