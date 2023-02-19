use byteorder::{BigEndian, ByteOrder};
use rand::random;
use sha2::{Digest, Sha256};

const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HashValue<const N: usize>([u8; N]);

impl<const N: usize> Default for HashValue<N> {
    fn default() -> Self {
        let data = [0u8; N];
        HashValue(data)
    }
}

impl<const N: usize> From<[u8; N]> for HashValue<N> {
    fn from(data: [u8; N]) -> Self {
        HashValue(data)
    }
}

impl From<[u8; 32]> for HashValue<24> {
    fn from(data: [u8; 32]) -> Self {
        let mut t = [0u8; 24];
        for index in 0..24 {
            t[index] = data[index];
        }
        HashValue(t)
    }
}

impl<const N: usize> AsRef<[u8]> for HashValue<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub type Sha256Digest = HashValue<32>;
pub type Sha192Digest = HashValue<24>;
pub type LmsIdentifier = [u8; 16];

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum LmotsAlgorithmType {
    LmotsReserved = 0,
    LmotsSha256N32W1 = 1,
    LmotsSha256N32W2 = 2,
    LmotsSha256N32W4 = 3,
    LmotsSha256N32W8 = 4,
    LmotsSha256N24W1 = 5,
    LmotsSha256N24W2 = 6,
    LmotsSha256N24W4 = 7,
    LmotsSha256N24W8 = 8,
}

#[derive(Debug)]
pub enum LmsAlgorithmType {
    LmsReserved = 0,
    LmsSha256N32H5 = 5,
    LmsSha256N32H10 = 6,
    LmsSha256N32H15 = 7,
    LmsSha256N32H20 = 8,
    LmsSha256N32H25 = 9,
    LmsSha256N24H5 = 10,
    LmsSha256N24H10 = 11,
    LmsSha256N24H15 = 12,
    LmsSha256N24H20 = 13,
    LmsSha256N24H25 = 14,
}
#[derive(Debug)]
pub struct LmotsSignature {
    ots_type: LmotsAlgorithmType,
    nonce: [u8; 32],
    y: Vec<Sha256Digest>,
}

#[derive(Debug)]
pub struct LmsSignature {
    pub q: u32,
    pub lmots_signature: LmotsSignature,
    pub sig_type: LmsAlgorithmType,
    pub lms_path: Vec<Sha256Digest>,
}

#[derive(Debug)]
pub struct LmotsParameter {
    algorithm_name: LmotsAlgorithmType,
    n: u8,
    w: u8,
    p: u16,
    ls: u8,
    sig_len: u16,
}

const LMOTS_P: [LmotsParameter; 9] = [
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsReserved,
        n: 0,
        w: 0,
        p: 0,
        ls: 0,
        sig_len: 0,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W1,
        n: 32,
        w: 1,
        p: 265,
        ls: 7,
        sig_len: 8516,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W2,
        n: 32,
        w: 2,
        p: 133,
        ls: 6,
        sig_len: 4292,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W4,
        n: 32,
        w: 4,
        p: 67,
        ls: 4,
        sig_len: 2180,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W8,
        n: 32,
        w: 8,
        p: 34,
        ls: 0,
        sig_len: 1124,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W1,
        n: 24,
        w: 1,
        p: 200,
        ls: 8,
        sig_len: 4828,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W2,
        n: 24,
        w: 2,
        p: 101,
        ls: 6,
        sig_len: 2452,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W4,
        n: 24,
        w: 4,
        p: 51,
        ls: 4,
        sig_len: 1252,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W8,
        n: 24,
        w: 8,
        p: 26,
        ls: 0,
        sig_len: 652,
    },
];

//do we actually need these?
fn u32str(i: u32) -> [u8; 4] {
    let mut buf = [0; 4];
    BigEndian::write_u32(&mut buf, i);
    return buf;
}

fn u16str(i: u16) -> [u8; 2] {
    let mut buf = [0; 2];
    BigEndian::write_u16(&mut buf, i);
    return buf;
}

fn u8str(i: u8) -> [u8; 1] {
    let mut buf = [0; 1];
    buf[0] = i;
    return buf;
}

pub fn get_lmots_parameters(algo_type: &LmotsAlgorithmType) -> &'static LmotsParameter {
    for i in &LMOTS_P {
        if i.algorithm_name == *algo_type {
            return i;
        }
    }
    panic!("Its all screwed")
}

pub fn get_lms_parameters(algo_type: &LmsAlgorithmType) -> (u8, u8) {
    match algo_type {
        LmsAlgorithmType::LmsSha256N32H5 => (32, 5),
        LmsAlgorithmType::LmsSha256N32H10 => (32, 10),
        LmsAlgorithmType::LmsSha256N32H15 => (32, 15),
        LmsAlgorithmType::LmsSha256N32H20 => (32, 20),
        LmsAlgorithmType::LmsSha256N32H25 => (32, 25),
        LmsAlgorithmType::LmsSha256N24H5 => (24, 5),
        LmsAlgorithmType::LmsSha256N24H10 => (24, 10),
        LmsAlgorithmType::LmsSha256N24H15 => (24, 15),
        LmsAlgorithmType::LmsSha256N24H20 => (24, 20),
        LmsAlgorithmType::LmsSha256N24H25 => (24, 25),
        LmsAlgorithmType::LmsReserved => {
            panic!("Its all screwed")
        }
    }
}

// follows pseudo code at https://www.rfc-editor.org/rfc/rfc8554#section-3.1.3
fn coefficient(s: &[u8], i: usize, w: usize) -> u8 {
    let blah: u16 = (1 << (w)) - 1;
    let index = i * w / 8;
    let b = s[index as usize];

    // extra logic to avoid the divide by 0
    // which a good compiler would notice only happens when w is 0 and that portion of the
    // expression could be skipped
    let mut shift = 8;
    if w != 0 {
        shift = 8 - (w * (i % (8 / w)) + w);
    }

    // Rust errors if we try to shift off all of the bits off from a value
    // some implementations 0 fill, others do some other filling.
    // we make this be 0
    let mut rs = 0;
    if shift < 8 {
        rs = b >> shift;
    }
    let small_blah = blah as u8;
    return small_blah & rs;
}

fn create_lmots_private_key(algo_type: &LmotsAlgorithmType) -> Vec<[u8; 32]> {
    let params = get_lmots_parameters(algo_type);
    let mut x = vec![];
    for _ in 0..params.p {
        let tmp: [u8; 32] = random();
        x.push(tmp);
    }
    return x;
}

fn calculate_ots_public_key(
    algo_type: &LmotsAlgorithmType,
    lms_identifier: &LmsIdentifier,
    q: &[u8; 4],
    x: &Vec<[u8; 32]>,
) -> Sha256Digest {
    let params = get_lmots_parameters(algo_type);
    let mut y = vec![[0u8; 32]; params.p as usize];
    for (i, xi) in x.iter().enumerate() {
        let mut tmp = xi.clone();
        let upper = (1 << params.w) - 1;
        for j in 0..upper {
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(q);
            hasher.update(u16str(i as u16));
            hasher.update(u8str(j as u8));
            hasher.update(tmp);
            let result = hasher.finalize();
            for (index, b) in result.iter().enumerate() {
                tmp[index] = *b;
            }
        }
        y[i] = tmp.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(lms_identifier);
    hasher.update(q);
    hasher.update(u16str(D_PBLC));
    for t in y {
        hasher.update(t);
    }
    let result = hasher.finalize();
    let mut final_result = [0u8; 32];
    for (index, b) in result.iter().enumerate() {
        final_result[index] = *b;
    }
    let return_value = Sha256Digest::from(final_result);
    return return_value;
}

// this is copied derived from section 5.2 of rfc 8554
fn create_lms_private_keys(
    tree_height: u8,
    ots_type: &LmotsAlgorithmType,
) -> (LmsIdentifier, u32, Vec<Vec<[u8; 32]>>) {
    let lms_identifier: LmsIdentifier = random();
    let upper = 1 << tree_height;
    let mut ots_private = vec![];
    for _ in 0..upper {
        ots_private.push(create_lmots_private_key(ots_type));
    }
    return (lms_identifier, 0, ots_private);
}

pub fn create_lms_tree(
    lms_type: &LmsAlgorithmType,
    ots_type: &LmotsAlgorithmType,
) -> (LmsIdentifier, u32, Vec<Sha256Digest>, Vec<Vec<[u8; 32]>>) {
    let (_, tree_height) = get_lms_parameters(lms_type);
    let num_nodes = 1 << tree_height + 1; // we will instantiate an array to store the entire tree
    let mut t_tree = vec![Sha256Digest::default(); num_nodes]; // the tree root will be at t_tree[1]
    let (lms_identifier, initial_q, private_keys) = create_lms_private_keys(tree_height, ots_type);
    if num_nodes != 2 * private_keys.len() {
        panic!("The tree needs to be twice the size of the number of private keys");
    }
    // Copy the public keys of the leaves into the leaves of the tree
    let initial_offset = private_keys.len();
    for offset in 0..private_keys.len() {
        let q = u32str(offset as u32);
        let ots_key =
            calculate_ots_public_key(ots_type, &lms_identifier, &q, &private_keys[offset]);
        let mut hasher = Sha256::new();
        hasher.update(lms_identifier);
        let r = (initial_offset + offset) as u32;
        hasher.update(u32str(r));
        hasher.update(u16str(D_LEAF));
        hasher.update(ots_key);
        let t_temp = hasher.finalize();
        let mut temp = [0u8; 32];
        for (index, b) in t_temp.iter().enumerate() {
            temp[index] = *b;
        }
        t_tree[initial_offset + offset] = Sha256Digest::from(temp);
    }
    // Now process each layer of tree from the bottom up
    for level in (1..(tree_height + 1)).rev() {
        let initial_offset = 1 << (level - 1);
        for offset in 0..initial_offset {
            let node_num = offset + initial_offset;
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(u32str(node_num));
            hasher.update(u16str(D_INTR));
            hasher.update(t_tree[2 * node_num as usize]);
            hasher.update(t_tree[(2 * node_num) as usize + 1]);

            let t_temp = hasher.finalize();
            let mut temp = [0u8; 32];
            for (index, b) in t_temp.iter().enumerate() {
                temp[index] = *b;
            }
            t_tree[node_num as usize] = Sha256Digest::from(temp);
        }
    }

    return (lms_identifier, initial_q, t_tree, private_keys);
}

fn checksum(algo_type: &LmotsAlgorithmType, input_string: &[u8]) -> u16 {
    let params = get_lmots_parameters(algo_type);
    let mut sum = 0u16;
    let upper_bound = params.n as u16 * (8 / params.w as u16);
    for i in 0..upper_bound {
        sum = sum + ((1 << params.w) - 1)
            - (coefficient(input_string, i as usize, params.w as usize) as u16);
    }
    let shifted = sum << params.ls;
    return shifted;
}

fn lmots_sign_message(
    algo_type: &LmotsAlgorithmType,
    input_string: &[u8],
    private_key: &Vec<[u8; 32]>,
    lms_identifier: &LmsIdentifier,
    q: &[u8; 4],
) -> LmotsSignature {
    let params = get_lmots_parameters(algo_type);
    let nonce: [u8; 32] = random(); // in the RFC this is the C value

    let mut y = vec![Sha256Digest::default(); params.p as usize];
    assert_eq!(private_key.len(), params.p as usize);
    let mut hasher = Sha256::new();
    hasher.update(lms_identifier);
    hasher.update(q);
    hasher.update(u16str(D_MESG));
    hasher.update(nonce);
    hasher.update(input_string);
    let tq = hasher.finalize();
    let mut message_hash_with_checksum = [0u8; 34]; // 2 extra bytes for the checksum.  assumes sha256
    for (index, b) in tq.iter().enumerate() {
        message_hash_with_checksum[index] = *b;
    }
    let checksum_q = checksum(algo_type, &message_hash_with_checksum);
    let be_checksum = u16str(checksum_q);
    message_hash_with_checksum[32] = be_checksum[0];
    message_hash_with_checksum[33] = be_checksum[1];

    for i in 0..params.p {
        let a = coefficient(&message_hash_with_checksum, i as usize, params.w as usize);
        let mut tmp = private_key[i as usize].clone();
        for j in 0..a {
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(q);
            hasher.update(u16str(i));
            hasher.update(u8str(j));
            hasher.update(tmp);
            let tt = hasher.finalize();
            for (index, b) in tt.iter().enumerate() {
                tmp[index] = *b;
            }
        }
        y[i as usize] = Sha256Digest::from(tmp.clone());
    }
    // TODO make this not hard coded type
    // currently ots_type is never checked anyway
    let signature = LmotsSignature {
        ots_type: LmotsAlgorithmType::LmotsSha256N32W4,
        nonce,
        y,
    };
    return signature;
}

fn candidate_ots_signature(
    algo_type: &LmotsAlgorithmType,
    lms_identifier: &LmsIdentifier,
    q: &[u8; 4],
    signature: &LmotsSignature,
    message: &[u8],
) -> Sha256Digest {
    let params = get_lmots_parameters(algo_type);
    let mut hasher = Sha256::new();
    let mut z = vec![Sha256Digest::default(); params.p as usize];
    hasher.update(lms_identifier);
    hasher.update(q);
    hasher.update(u16str(D_MESG));
    hasher.update(signature.nonce);
    hasher.update(message);
    let tq = hasher.finalize();
    let mut message_hash_with_checksum = [0u8; 34]; // 2 extra bytes for the checksum
    for (index, b) in tq.iter().enumerate() {
        message_hash_with_checksum[index] = *b;
    }
    let checksum_q = checksum(algo_type, &message_hash_with_checksum);
    let be_checksum = u16str(checksum_q);
    message_hash_with_checksum[32] = be_checksum[0];
    message_hash_with_checksum[33] = be_checksum[1];

    for i in 0..params.p {
        let a = coefficient(&message_hash_with_checksum, i as usize, params.w as usize);
        let mut tmp = signature.y[i as usize].clone();
        let t_upper: u16 = (1 << params.w) - 1; // subtract with overflow?
        let upper = t_upper as u8;
        for j in a..upper {
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(q);
            hasher.update(u16str(i));
            hasher.update(u8str(j));
            hasher.update(tmp);
            let tt = hasher.finalize();
            let mut blah = [0u8; 32];
            for (index, b) in tt.iter().enumerate() {
                blah[index] = *b;
            }
            tmp = Sha256Digest::from(blah);
        }
        z[i as usize] = tmp;
    }
    let mut hasher = Sha256::new();
    hasher.update(lms_identifier);
    hasher.update(q);
    hasher.update(u16str(D_PBLC));
    for t in z {
        hasher.update(t);
    }
    let result = hasher.finalize();
    let mut final_result = [0u8; 32];
    for (index, b) in result.iter().enumerate() {
        final_result[index] = *b;
    }
    return Sha256Digest::from(final_result);
}

fn verify_ots_signature(
    algo_type: &LmotsAlgorithmType,
    lms_identifier: &LmsIdentifier,
    q: &[u8; 4],
    public_key: &Sha256Digest,
    signature: &LmotsSignature,
    message: &[u8],
) -> bool {
    let final_result = candidate_ots_signature(algo_type, lms_identifier, q, &signature, &message);

    if final_result != *public_key {
        return false;
    }
    return true;
}

pub fn lms_sign_message(
    algo_type: &LmotsAlgorithmType,
    input_string: &[u8],
    t_tree: &Vec<Sha256Digest>,
    tree_height: u8,
    private_key: &Vec<[u8; 32]>,
    lms_identifier: &LmsIdentifier,
    q: u32,
) -> LmsSignature {
    let q_str = u32str(q);
    let lmots_sig =
        lmots_sign_message(algo_type, input_string, private_key, lms_identifier, &q_str);
    let mut path = vec![];

    let mut node_num = (1 << tree_height) + q;
    let mut sibling = node_num ^ 1;
    path.push(t_tree[sibling as usize]);
    for _ in 1..tree_height {
        node_num = node_num >> 1;
        sibling = node_num ^ 1;
        path.push(t_tree[sibling as usize]);
    }
    let signature = LmsSignature {
        q,
        sig_type: LmsAlgorithmType::LmsSha256N32H10,
        lmots_signature: lmots_sig,
        lms_path: path,
    };
    return signature;
}

pub fn verify_lms_signature(
    tree_height: u8,
    algo_type: &LmotsAlgorithmType,
    input_string: &[u8],
    lms_identifier: &LmsIdentifier,
    q: u32,
    lms_public_key: &Sha256Digest,
    lms_sig: &LmsSignature,
) -> bool {
    let q_str = u32str(q);
    let candidate_key = candidate_ots_signature(
        algo_type,
        lms_identifier,
        &q_str,
        &lms_sig.lmots_signature,
        input_string,
    );
    let mut node_num = (1 << tree_height) + q;
    let mut hasher = Sha256::new();
    hasher.update(lms_identifier);
    hasher.update(u32str(node_num));
    hasher.update(u16str(D_LEAF));
    hasher.update(candidate_key);
    let t_temp = hasher.finalize();
    let mut temp = [0u8; 32];
    for (index, b) in t_temp.iter().enumerate() {
        temp[index] = *b;
    }
    let mut i = 0;
    while node_num > 1 {
        if node_num % 2 == 1 {
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(u32str(node_num / 2));
            hasher.update(u16str(D_INTR));
            hasher.update(lms_sig.lms_path[i]);
            hasher.update(temp);
            let t_temp = hasher.finalize();
            for (index, b) in t_temp.iter().enumerate() {
                temp[index] = *b;
            }
        } else {
            let mut hasher = Sha256::new();
            hasher.update(lms_identifier);
            hasher.update(u32str(node_num / 2));
            hasher.update(u16str(D_INTR));
            hasher.update(temp);
            hasher.update(lms_sig.lms_path[i]);
            let t_temp = hasher.finalize();
            for (index, b) in t_temp.iter().enumerate() {
                temp[index] = *b;
            }
        }
        node_num = node_num / 2;
        i = i + 1;
    }
    let candidate_key = Sha256Digest::from(temp);
    if candidate_key != *lms_public_key {
        println!("Candidate LMS public key is {:?}", temp);
        println!("The provided LMS key is     {:?}", lms_public_key);
        return false;
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lmots_params_test() {
        let result = get_lmots_parameters(&LmotsAlgorithmType::LmotsSha256N32W4);
        assert_eq!(result.n, 32);
    }

    // test case from https://datatracker.ietf.org/doc/html/rfc8554#section-3.1.3
    #[test]
    fn test_coefficient() {
        let input_value = [0x12u8, 0x34u8];
        let result = coefficient(&input_value, 7, 1);
        assert_eq!(result, 0);

        let result = coefficient(&input_value, 0, 4);
        assert_eq!(result, 1);
    }
}
