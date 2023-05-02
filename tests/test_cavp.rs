use serde::Deserialize;
use std::fs;

// the JSON coming from the CAVP is not snake case, so we need to disable the
// warning for that and we don't use all the fields, so we need to disable
// the dead code warning
#[allow(non_snake_case, dead_code)]
#[derive(Deserialize, Debug)]
struct LmsCavpSuite {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<LmsTestGroup>,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize, Debug)]
struct LmsTestGroup {
    tgId: u32,
    testType: String,
    lmsMode: String,
    lmOtsMode: String,
    publicKey: String,
    tests: Vec<LmsTest>,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize, Debug)]
struct LmsTest {
    tcId: u32,
    testPassed: bool,
    message: String,
    signature: String,
    reason: String,
}

#[test]
fn test_many() {
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
            tree_height,
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
    println!("{} out of {} signatures matched", passed, num_keys);
}

#[test]
fn test_cavp_32() {
    let contents =
        fs::read_to_string("tests/cavp_32.json").expect("Should have been able to read the file");
    let suite: LmsCavpSuite = serde_json::from_str(&contents).unwrap();
    for tg in suite.testGroups {
        let pub_key =
            lms_hss::parse_public_contents::<32>(&hex::decode(tg.publicKey).unwrap()).unwrap();
        let mut failed = 0;
        let mut passed = 0;
        for t in &tg.tests {
            let sig = hex::decode(&t.signature).unwrap();
            let lms_sig_result = lms_hss::parse_signature_contents::<32>(&sig);
            if let Err(..) = lms_sig_result {
                if !t.testPassed {
                    passed += 1;
                    continue;
                } else {
                    println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                    failed += 1;
                    continue;
                }
            } else {
                let lms_sig = lms_sig_result.unwrap();
                let success_result = lms_hss::verify_lms_signature(
                    &hex::decode(&t.message).unwrap(),
                    &pub_key,
                    &lms_sig,
                );
                if success_result.is_err() {
                    if !t.testPassed {
                        passed += 1;
                        continue;
                    } else {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        failed += 1;
                        continue;
                    }
                } else {
                    let success = success_result.unwrap();
                    if success != t.testPassed {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        failed += 1;
                    } else {
                        passed += 1;
                    }
                }
            }
        }
        println!("passed: {} failed: {} in tg {}", passed, failed, tg.tgId);
        assert_eq!(passed, tg.tests.len());
    }
}

#[test]
fn test_cavp_24() {
    let contents =
        fs::read_to_string("tests/cavp_24.json").expect("Should have been able to read the file");
    let suite: LmsCavpSuite = serde_json::from_str(&contents).unwrap();
    for tg in suite.testGroups {
        let pub_key =
            lms_hss::parse_public_contents::<24>(&hex::decode(tg.publicKey).unwrap()).unwrap();
        let mut failed = 0;
        let mut passed = 0;
        for t in &tg.tests {
            let sig = hex::decode(&t.signature).unwrap();
            let lms_sig_result = lms_hss::parse_signature_contents::<24>(&sig);
            if let Err(..) = lms_sig_result {
                if !t.testPassed {
                    passed += 1;
                    continue;
                } else {
                    println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                    failed += 1;
                    continue;
                }
            } else {
                let lms_sig = lms_sig_result.unwrap();
                let success_result = lms_hss::verify_lms_signature(
                    &hex::decode(&t.message).unwrap(),
                    &pub_key,
                    &lms_sig,
                );
                if success_result.is_err() {
                    if !t.testPassed {
                        passed += 1;
                        continue;
                    } else {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        failed += 1;
                        continue;
                    }
                } else {
                    let success = success_result.unwrap();
                    if success != t.testPassed {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        failed += 1;
                    } else {
                        passed += 1;
                    }
                }
            }
        }
        println!("passed: {} failed: {} in tg {}", passed, failed, tg.tgId);
        assert_eq!(passed, tg.tests.len());
    }
}
