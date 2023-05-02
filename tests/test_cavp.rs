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
fn test_cavp_32() {
    let contents =
        fs::read_to_string("tests/cavp_32.json").expect("Should have been able to read the file");
    let suite: LmsCavpSuite = serde_json::from_str(&contents).unwrap();
    for tg in suite.testGroups {
        let pub_key =
            lms_hss::parse_public_contents::<32>(&hex::decode(tg.publicKey).unwrap()).unwrap();
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
                    continue;
                }
            } else {
                let lms_sig = lms_sig_result.unwrap();
                let success_result = lms_hss::verify_lms_signature(
                    &hex::decode(&t.message).unwrap(),
                    &pub_key,
                    &lms_sig,
                );
                if let Err(..) = success_result {
                    if !t.testPassed {
                        passed += 1;
                        continue;
                    } else {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        continue;
                    }
                } else {
                    let success = success_result.unwrap();
                    if success != t.testPassed {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                    } else {
                        passed += 1;
                    }
                }
            }
        }
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
                    continue;
                }
            } else {
                let lms_sig = lms_sig_result.unwrap();
                let success_result = lms_hss::verify_lms_signature(
                    &hex::decode(&t.message).unwrap(),
                    &pub_key,
                    &lms_sig,
                );
                if let Err(..) = success_result {
                    if !t.testPassed {
                        passed += 1;
                        continue;
                    } else {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                        continue;
                    }
                } else {
                    let success = success_result.unwrap();
                    if success != t.testPassed {
                        println!("test failed tg: {} tcId: {}", tg.tgId, t.tcId);
                    } else {
                        passed += 1;
                    }
                }
            }
        }
        assert_eq!(passed, tg.tests.len());
    }
}
