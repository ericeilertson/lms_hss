fn main() {
    let message = "this is the message I want signed".as_bytes();
    let the_lms_type = &lms_hss::LmsAlgorithmType::LmsSha256N32H10;
    let the_ots_type = &lms_hss::LmotsAlgorithmType::LmotsSha256N32W4;
    let (_, tree_height) = lms_hss::get_lms_parameters(the_lms_type);
    let (lms_identifier, initial_q, t_tree, private_keys) =
        lms_hss::create_lms_tree::<32, 67>(the_lms_type, the_ots_type).unwrap();
    let lms_public_key = t_tree[1];

    let num_keys = 1 << tree_height;
    let mut passed = 0;
    for offset_q in 0..num_keys {
        let the_q_to_use = initial_q + offset_q;
        let lms_sig = lms_hss::lms_sign_message(
            the_ots_type,
            the_lms_type,
            message,
            &t_tree,
            tree_height,
            &private_keys[the_q_to_use as usize],
            &lms_identifier,
            the_q_to_use,
        ).unwrap();

        let valid = lms_hss::verify_lms_signature(
            tree_height,
            the_ots_type,
            message,
            &lms_identifier,
            the_q_to_use,
            &lms_public_key,
            &lms_sig,
        ).unwrap();
        if valid {
            passed += 1;
        }
        assert!(valid);
    }
    println!("{} out of {} signatures matched", passed, num_keys);
}
