const std::string ruby_test_string_04 = R"(
$test_data_04 = {
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
    "random_string_in_between": false,
    "dev_info" => {
        "gender" => "raccoon",
        :age => 256.3,
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
        3.14 => :PI,
    },
    "end_of_data" => true,
}
)";

const std::string ruby_code_04 = R"(
OSSP.serialize($test_data)
$result = OSSP.deserialize()
$test_diff = deep_diff($test_data_04, $result)
)";