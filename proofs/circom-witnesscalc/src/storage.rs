use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};
use prost::Message;
use crate::graph::Node;
use crate::InputSignalsInfo;
use crate::proto::InputNode;

const WITNESSCALC_GRAPH_MAGIC: &[u8] = b"wtns.graph.001";

fn serialize_witnesscalc_graph(
    nodes: &Vec<Node>, witness_signals: &Vec<usize>,
    input_signals: InputSignalsInfo) -> Vec<u8> {

    let mut buf: Vec<u8> = Vec::new();
    buf.write_all(WITNESSCALC_GRAPH_MAGIC).unwrap();

    buf.write_u32::<LittleEndian>(nodes.len() as u32).unwrap();

    for node in nodes {
        let node = match node {
            Node::Input(i) => {
                crate::proto::node::Node::Input(InputNode {
                    idx: i.clone() as u32 })
            }
            Node::Constant(c) => {
                let i = crate::proto::BigUInt {
                    value_le: c.to_le_bytes_vec() };
                crate::proto::node::Node::Constant(crate::proto::ConstantNode {
                    value: Some(i) })
            }
            Node::UnoOp(op, a) => {
                let op = crate::proto::UnoOp::from(op);
                crate::proto::node::Node::UnoOp(crate::proto::UnoOpNode {
                    op: op as i32,
                    a_idx: a.clone() as u32 })
            }
            Node::Op(op, a, b) => {
                crate::proto::node::Node::DuoOp(crate::proto::DuoOpNode {
                    op: crate::proto::DuoOp::from(op) as i32,
                    a_idx: a.clone() as u32,
                    b_idx: b.clone() as u32 })
            }
            Node::TresOp(op, a, b, c) => {
                crate::proto::node::Node::TresOp(crate::proto::TresOpNode {
                    op: crate::proto::TresOp::from(op) as i32,
                    a_idx: a.clone() as u32,
                    b_idx: b.clone() as u32,
                    c_idx: c.clone() as u32 })
            }
            Node::MontConstant(_) => {
                panic!("Not implemented");
            }
        };
        node.encode(&mut buf);
    }

    let witnessSigs = crate::proto::GraphMetadata {
        witness_signals: witness_signals.iter().map(|x| *x as u32).collect::<Vec<u32>>(),
        inputs: input_signals.iter().map(|(k, v)| {
            let sig = crate::proto::SignalDescription {
                offset: v.0 as u32,
                len: v.1 as u32 };
            (k.clone(), sig)
        }).collect()
    };

    witnessSigs.encode(&mut buf).unwrap();

    buf
}

fn deserialize_witnesscalc_graph<T: std::io::BufRead>(_r: T) {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use ruint::aliases::U256;
    use crate::graph::{Operation, TresOperation, UnoOperation};
    use super::*;

    #[test]
    fn test_deserialize_inputs() {
        let nodes = vec![
            Node::Input(0),
            Node::Constant(U256::from(1)),
            Node::UnoOp(UnoOperation::Id, 4),
            Node::Op(Operation::Mul, 5, 6),
            Node::TresOp(TresOperation::TernCond, 7, 8, 9),
        ];

        let witness_signals = vec![4, 1];

        let mut input_signals: InputSignalsInfo = HashMap::new();
        input_signals.insert("sig1".to_string(), (1, 3));
        input_signals.insert("sig2".to_string(), (5, 1));

        let r = serialize_witnesscalc_graph(&nodes, &witness_signals, input_signals);
        println!("{}", r.len());
    }
}