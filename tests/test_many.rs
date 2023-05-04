#[test]
fn test_many_24() {
    let message = "this is the message I want signed".as_bytes();
    let the_lms_type = &lms_hss::LmsAlgorithmType::LmsSha256N24H10;
    let the_ots_type = &lms_hss::LmotsAlgorithmType::LmotsSha256N24W4;
    let (_, tree_height) = lms_hss::get_lms_parameters(the_lms_type).unwrap();
    let (lms_public_key, lms_tree) =
        lms_hss::create_lms_tree::<24>(the_lms_type, the_ots_type).unwrap();

    let num_keys = 1 << tree_height;
    let mut passed = 0;
    //println!("About to perform {} sha256/192 sign and verifies", num_keys);
    for offset_q in 0..num_keys {
        let the_q_to_use = lms_tree.q + offset_q;
        let lms_sig = lms_hss::lms_sign_message(
            the_ots_type,
            the_lms_type,
            message,
            &lms_tree.private_keys[the_q_to_use as usize],
            the_q_to_use,
            &lms_tree,
        )
        .unwrap();

        let valid = lms_hss::verify_lms_signature(message, &lms_public_key, &lms_sig).unwrap();
        if valid {
            passed += 1;
        }
        assert!(valid);
    }
    assert_eq!(passed, num_keys);
}

#[test]
fn test_many_32() {
    let message = "this is the message I want signed".as_bytes();
    let the_lms_type = &lms_hss::LmsAlgorithmType::LmsSha256N32H10;
    let the_ots_type = &lms_hss::LmotsAlgorithmType::LmotsSha256N32W4;
    let (_, tree_height) = lms_hss::get_lms_parameters(the_lms_type).unwrap();
    let (lms_public_key, lms_tree) =
        lms_hss::create_lms_tree::<32>(the_lms_type, the_ots_type).unwrap();

    let num_keys = 1 << tree_height;
    let mut passed = 0;
    for offset_q in 0..num_keys {
        let the_q_to_use = lms_tree.q + offset_q;
        let lms_sig = lms_hss::lms_sign_message(
            the_ots_type,
            the_lms_type,
            message,
            &lms_tree.private_keys[the_q_to_use as usize].clone(),
            the_q_to_use,
            &lms_tree,
        )
        .unwrap();

        let valid = lms_hss::verify_lms_signature(message, &lms_public_key, &lms_sig).unwrap();
        if valid {
            passed += 1;
        }
        assert!(valid);
    }
    assert_eq!(passed, num_keys);
}

#[test]
fn test_combinations_32() {
    let message = "this is the message I want signed".as_bytes();
    let lms_types = [
        lms_hss::LmsAlgorithmType::LmsSha256N32H5,
        lms_hss::LmsAlgorithmType::LmsSha256N32H10,
        //lms_hss::LmsAlgorithmType::LmsSha256N32H15, // adding this takes about 25 seconds
        //lms_hss::LmsAlgorithmType::LmsSha256N32H20, // this adds about 13 minutes
        //lms_hss::LmsAlgorithmType::LmsSha256N32H25,
    ];
    let ots_types = [
        lms_hss::LmotsAlgorithmType::LmotsSha256N32W1,
        lms_hss::LmotsAlgorithmType::LmotsSha256N32W2,
        lms_hss::LmotsAlgorithmType::LmotsSha256N32W4,
        lms_hss::LmotsAlgorithmType::LmotsSha256N32W8,
    ];
    for lms_type in lms_types.iter() {
        for ots_type in ots_types.iter() {
            //println!("Testing lms_type {:?} ots_type {:?}", lms_type, ots_type);
            //let (_, tree_height) = lms_hss::get_lms_parameters(lms_type).unwrap();
            let (lms_public_key, lms_tree) =
                lms_hss::create_lms_tree::<32>(lms_type, ots_type).unwrap();

            //let num_keys = 1 << tree_height;
            let num_keys = 10;
            let mut passed = 0;
            for offset_q in 0..num_keys {
                let the_q_to_use = lms_tree.q + offset_q;
                let lms_sig = lms_hss::lms_sign_message(
                    ots_type,
                    lms_type,
                    message,
                    &lms_tree.private_keys[the_q_to_use as usize].clone(),
                    the_q_to_use,
                    &lms_tree,
                )
                .unwrap();

                let valid =
                    lms_hss::verify_lms_signature(message, &lms_public_key, &lms_sig).unwrap();
                if valid {
                    passed += 1;
                }
                assert!(valid);
            }
            assert_eq!(passed, num_keys);
        }
    }
}

#[test]
fn test_combinations_24() {
    let message = "this is the message I want signed".as_bytes();
    let lms_types = [
        lms_hss::LmsAlgorithmType::LmsSha256N24H5,
        lms_hss::LmsAlgorithmType::LmsSha256N24H10,
        //lms_hss::LmsAlgorithmType::LmsSha256N24H15,  // adding this takes about 15 seconds
        //lms_hss::LmsAlgorithmType::LmsSha256N24H20,  // and this adds about 8 minutes
        //lms_hss::LmsAlgorithmType::LmsSha256N24H25,  // and this takes forever
    ];
    let ots_types = [
        lms_hss::LmotsAlgorithmType::LmotsSha256N24W1,
        lms_hss::LmotsAlgorithmType::LmotsSha256N24W2,
        lms_hss::LmotsAlgorithmType::LmotsSha256N24W4,
        lms_hss::LmotsAlgorithmType::LmotsSha256N24W8,
    ];
    for lms_type in lms_types.iter() {
        for ots_type in ots_types.iter() {
            //println!("Testing lms_type {:?} ots_type {:?}", lms_type, ots_type);
            //let (_, tree_height) = lms_hss::get_lms_parameters(lms_type).unwrap();
            let (lms_public_key, lms_tree) =
                lms_hss::create_lms_tree::<24>(lms_type, ots_type).unwrap();

            //let num_keys = 1 << tree_height;
            let num_keys = 10;
            let mut passed = 0;
            for offset_q in 0..num_keys {
                let the_q_to_use = lms_tree.q + offset_q;
                let lms_sig = lms_hss::lms_sign_message(
                    ots_type,
                    lms_type,
                    message,
                    &lms_tree.private_keys[the_q_to_use as usize].clone(),
                    the_q_to_use,
                    &lms_tree,
                )
                .unwrap();

                let valid =
                    lms_hss::verify_lms_signature(message, &lms_public_key, &lms_sig).unwrap();
                if valid {
                    passed += 1;
                }
                assert!(valid);
            }
            assert_eq!(passed, num_keys);
        }
    }
}
