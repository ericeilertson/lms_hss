use lms_hss::{
    get_lmots_parameters, get_lms_parameters, lookup_lmots_algorithm_type, LmotsAlgorithmType,
    LmsAlgorithmType,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_lookup_lmots_algorithm_type(value in 1u32..8u32) {
        prop_assert!(lookup_lmots_algorithm_type(value).is_ok());
    }
}

proptest! {
    #[test]
    fn test_lookup_lmots_algorithm_errors(value in 9u32..100u32) {
        prop_assert!(lookup_lmots_algorithm_type(value).is_err());
    }
}

fn _full_lms_enum_strategy() -> impl Strategy<Value = LmsAlgorithmType> {
    prop_oneof![
        Just(LmsAlgorithmType::LmsSha256N32H5),
        Just(LmsAlgorithmType::LmsSha256N32H10),
        Just(LmsAlgorithmType::LmsSha256N32H15),
        Just(LmsAlgorithmType::LmsSha256N32H20),
        Just(LmsAlgorithmType::LmsSha256N32H25),
        Just(LmsAlgorithmType::LmsSha256N24H5),
        Just(LmsAlgorithmType::LmsSha256N24H10),
        Just(LmsAlgorithmType::LmsSha256N24H15),
        Just(LmsAlgorithmType::LmsSha256N24H20),
        Just(LmsAlgorithmType::LmsSha256N24H25),
    ]
}

// this function avoids the full LMS enum strategy because it takes too long to run
fn lms_enum_strategy() -> impl Strategy<Value = LmsAlgorithmType> {
    prop_oneof![
        Just(LmsAlgorithmType::LmsSha256N32H5),
        Just(LmsAlgorithmType::LmsSha256N32H10),
        //Just(LmsAlgorithmType::LmsSha256N32H15),
        //Just(LmsAlgorithmType::LmsSha256N32H20),
        //Just(LmsAlgorithmType::LmsSha256N32H25),
        Just(LmsAlgorithmType::LmsSha256N24H5),
        Just(LmsAlgorithmType::LmsSha256N24H10),
        //Just(LmsAlgorithmType::LmsSha256N24H15),
        //Just(LmsAlgorithmType::LmsSha256N24H20),
        //Just(LmsAlgorithmType::LmsSha256N24H25),
    ]
}

//function to generate a random LmotsAlgorithmType
fn lmots_enum_strategy() -> impl Strategy<Value = LmotsAlgorithmType> {
    prop_oneof![
        Just(LmotsAlgorithmType::LmotsSha256N32W1),
        Just(LmotsAlgorithmType::LmotsSha256N32W2),
        Just(LmotsAlgorithmType::LmotsSha256N32W4),
        Just(LmotsAlgorithmType::LmotsSha256N32W8),
        Just(LmotsAlgorithmType::LmotsSha256N24W1),
        Just(LmotsAlgorithmType::LmotsSha256N24W2),
        Just(LmotsAlgorithmType::LmotsSha256N24W4),
        Just(LmotsAlgorithmType::LmotsSha256N24W8),
    ]
}

proptest! {
    #[test]
    fn test_get_lmots_params(value in lmots_enum_strategy()) {
        prop_assert!(get_lmots_parameters(&value).is_ok());
    }
}

proptest! {
    #[test]
    fn test_get_lms_params(value in lms_enum_strategy()) {
        prop_assert!(get_lms_parameters(&value).is_ok());
    }
}

proptest! {
    #[test]
    #[ignore]
    // function to test create_lms_tree
    fn test_create_lms_tree(lms_type in lms_enum_strategy(), lmots_type in lmots_enum_strategy()) {
        let result = lms_hss::create_lms_tree::<32>(&lms_type, &lmots_type);
        if matches!(lms_type, LmsAlgorithmType::LmsSha256N32H5 | LmsAlgorithmType::LmsSha256N32H10 | LmsAlgorithmType::LmsSha256N32H15 | LmsAlgorithmType::LmsSha256N32H20 | LmsAlgorithmType::LmsSha256N32H25) {
            if matches!(lmots_type, LmotsAlgorithmType::LmotsSha256N32W1 | LmotsAlgorithmType::LmotsSha256N32W2 | LmotsAlgorithmType::LmotsSha256N32W4 | LmotsAlgorithmType::LmotsSha256N32W8) {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        } else if matches!(lms_type, LmsAlgorithmType::LmsSha256N24H5 | LmsAlgorithmType::LmsSha256N24H10 | LmsAlgorithmType::LmsSha256N24H15 | LmsAlgorithmType::LmsSha256N24H20 | LmsAlgorithmType::LmsSha256N24H25) {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_err());
        }
    }


}

fn main() {
    test_lookup_lmots_algorithm_type();
    test_lookup_lmots_algorithm_errors();
    test_get_lmots_params();
    test_get_lms_params();
    test_create_lms_tree();
}
