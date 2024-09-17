#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// #[allow(dead_code)]
mod field;
pub mod graph;
mod storage;

use std::collections::HashMap;
use std::ffi::{c_void, c_char, c_int, CStr};
use std::slice::from_raw_parts;
use ruint::aliases::U256;
use ruint::ParseError;
use crate::graph::Node;
use wtns_file::FieldElement;
use crate::field::M;

pub type InputSignalsInfo = HashMap<String, (usize, usize)>;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/circom_witnesscalc.proto.rs"));
}

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
// include!("bindings.rs");

fn prepare_status(status: *mut gw_status_t, code: GW_ERROR_CODE, error_msg: &str) {
    if !status.is_null() {
        let bs = error_msg.as_bytes();
        unsafe {
            (*status).code = code;
            (*status).error_msg = libc::malloc(bs.len()+1) as *mut c_char;
            libc::memcpy((*status).error_msg as *mut c_void, bs.as_ptr() as *mut c_void, bs.len());
            *((*status).error_msg.offset(bs.len() as isize)) = 0;
        }
    }
}

#[no_mangle]
pub extern "C" fn gw_calc_witness(
    inputs: *const c_char,
    graph_data: *const c_void, graph_data_len: usize,
    wtns_data: *mut *mut c_void, wtns_len: *mut usize,
    status: *mut gw_status_t) -> c_int {

    if inputs.is_null() {
        prepare_status(status, GW_ERROR_CODE_ERROR, "inputs is null");
        return 1;
    }

    if graph_data.is_null() {
        prepare_status(status, GW_ERROR_CODE_ERROR, "graph_data is null");
        return 1;
    }

    if graph_data_len == 0 {
        prepare_status(status, GW_ERROR_CODE_ERROR, "graph_data_len is 0");
        return 1;
    }

    let graph_data_r: &[u8];
    unsafe {
        graph_data_r = from_raw_parts(graph_data as *const u8, graph_data_len);
    }


    let inputs_str: &str;
    unsafe {
        let c = CStr::from_ptr(inputs);
        match c.to_str() {
            Ok(x) => {
                inputs_str = x;
            }
            Err(e) => {
                prepare_status(status, GW_ERROR_CODE_ERROR, format!("Failed to parse inputs: {}", e).as_str());
                return 1;
            }
        }
    }

    let witness = match calc_witness(inputs_str, graph_data_r) {
        Ok(witness) => witness,
        Err(e) => {
            prepare_status(status, GW_ERROR_CODE_ERROR, format!("Failed to calculate witness: {:?}", e).as_str());
            return 1;
        }
    };

    let witness_data = wtns_from_witness(witness);

    unsafe {
        *wtns_len = witness_data.len();
        *wtns_data = libc::malloc(witness_data.len()) as *mut c_void;
        libc::memcpy(*wtns_data, witness_data.as_ptr() as *const c_void, witness_data.len());
    }

    prepare_status(status, GW_ERROR_CODE_ERROR, "test error");

    println!("OK");

    return 0;
}

// create a wtns file bytes from witness (array of field elements)
pub fn wtns_from_witness(witness: Vec<U256>) -> Vec<u8> {
    let vec_witness: Vec<FieldElement<32>> = witness.iter().map(|a| u256_to_field_element(a)).collect();
    let mut buf = Vec::new();
    let mut wtns_f = wtns_file::WtnsFile::from_vec(vec_witness, u256_to_field_element(&M));
    wtns_f.version = 2;
    // We write into the buffer, so we should not have any errors here.
    // Panic in case of out of memory is fine.
    wtns_f.write(&mut buf).unwrap();
    buf
}

pub fn calc_witness(inputs: &str, graph_data: &[u8]) -> Result<Vec<U256>, Error> {

    let inputs = deserialize_inputs(inputs.as_bytes())?;

    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, InputSignalsInfo) =
        postcard::from_bytes(graph_data).unwrap();

    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(&nodes));
    populate_inputs(&inputs, &input_mapping, &mut inputs_buffer);

    Ok(graph::evaluate(&nodes, inputs_buffer.as_slice(), &signals))
}

fn get_inputs_size(nodes: &Vec<Node>) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for &node in nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

fn populate_inputs(
    input_list: &HashMap<String, Vec<U256>>, inputs_info: &InputSignalsInfo,
    input_buffer: &mut Vec<U256>) {
    for (key, value) in input_list {
        let (offset, len) = inputs_info[key];
        if len != value.len() {
            panic!("Invalid input length for {}", key);
        }
        // println!("input {}, offset {}, len {}", key, offset, len);

        for (i, v) in value.iter().enumerate() {
            input_buffer[offset + i] = v.clone();
        }
    }
}

fn u256_to_field_element(a: &U256) -> FieldElement<32> {
    let x: [u8; 32] = a.as_le_slice().try_into().unwrap();
    x.into()
}


/// Allocates inputs vec with position 0 set to 1
fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

#[derive(Debug)]
pub enum Error {
    InputsUnmarshal(String),
    InputFieldNumberParseError(ParseError)
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::InputFieldNumberParseError(e)
    }
}

pub fn deserialize_inputs(inputs_data: &[u8]) -> Result<HashMap<String, Vec<U256>>, Error> {
    let v: serde_json::Value = serde_json::from_slice(inputs_data).unwrap();

    let map = if let serde_json::Value::Object(map) = v {
        map
    } else {
        return Err(Error::InputsUnmarshal("inputs must be an object".to_string()));
    };

    let mut inputs: HashMap<String, Vec<U256>> = HashMap::new();
    for (k, v) in map {
        match v {
            serde_json::Value::String(s) => {
                let i = U256::from_str_radix(s.as_str(),10)?;
                inputs.insert(k.clone(), vec![i]);
            }
            serde_json::Value::Number(n) => {
                if !n.is_u64() {
                    return Err(Error::InputsUnmarshal("signal value is not a positive integer".to_string()));
                }
                let i = U256::from(n.as_u64().unwrap());
                inputs.insert(k.clone(), vec![i]);
            }
            serde_json::Value::Array(ss) => {
                let mut vals: Vec<U256> = Vec::with_capacity(ss.len());
                for v in &ss {
                    let i = match v {
                        serde_json::Value::String(s) => {
                            U256::from_str_radix(s.as_str(),10)?
                        }
                        serde_json::Value::Number(n) => {
                            if !n.is_u64() {
                                return Err(Error::InputsUnmarshal("signal value is not a positive integer".to_string()));
                            }
                            U256::from(n.as_u64().unwrap())
                        }
                        _ => {
                            return Err(Error::InputsUnmarshal("inputs must be a string".to_string()));
                        }
                    };
                    vals.push(i);
                }
                inputs.insert(k.clone(), vals);
            }
            _ => {
                return Err(Error::InputsUnmarshal(format!(
                    "value for key {} must be an a number as a string, as a number of an array of strings of numbers",
                    k.clone())));
            }
        }
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use prost::Message;
    use ruint::aliases::U256;
    use ruint::{uint};
    use crate::proto::InputNode;

    #[test]
    fn test_ok() {
        let data = r#"
    {
        "key1": ["123", "456", 100500],
        "key2": "789",
        "key3": 123123
    }
    "#;
        let inputs = super::deserialize_inputs(data.as_bytes()).unwrap();
        let want: HashMap<String, Vec<U256>> = [
            ("key1".to_string(), vec![uint!(123_U256), uint!(456_U256), uint!(100500_U256)]),
            ("key2".to_string(), vec![uint!(789_U256)]),
            ("key3".to_string(), vec![uint!(123123_U256)]),
        ].iter().cloned().collect();

        // Check that both maps have the same length
        assert_eq!(inputs.len(), want.len(), "HashMaps do not have the same length");

        // Iterate and compare each key-value pair
        for (key, value) in &inputs {
            assert_eq!(want.get(key), Some(value), "Mismatch at key: {}", key);
        }
    }

    #[test]
    fn test_ok2() {
        let i: InputNode = InputNode {
            idx: 1,
        };
        let v = i.encode_to_vec();
        println!("{:?}", v.len());
    }

}