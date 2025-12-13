#include <string>

const std::string ruby_test_string_05 = R"(
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

const std::string ruby_code_05 = R"(
$test_meta_data = "One morning, when Gregor Samsa woke from troubled dreams, he found himself transformed in his bed into a horrible vermin. He lay on his armour-like back, and if he lifted his head a little he could see his brown belly, slightly domed and divided by arches into stiff sections."
OSSP.serialize($test_data, $test_meta_data)
$result, $result_meta = OSSP.deserialize()
puts $result
puts $result_meta
$test_diff = deep_diff($test_data, $result)
)";