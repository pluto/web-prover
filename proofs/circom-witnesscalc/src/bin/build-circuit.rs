use compiler::circuit_design::template::{TemplateCode};
use compiler::compiler_interface::{run_compiler, Circuit, Config};
use compiler::intermediate_representation::ir_interface::{AddressType, CallBucket, ComputeBucket, CreateCmpBucket, FinalData, InputInformation, Instruction, InstructionPointer, LoadBucket, LocationRule, OperatorType, ReturnBucket, ReturnType, StatusInput, StoreBucket, ValueBucket, ValueType};
use constraint_generation::{build_circuit, BuildConfig};
use program_structure::error_definition::Report;
use ruint::aliases::U256;
use ruint::uint;
use std::collections::HashMap;
use std::{env, fmt, fs};
use std::error::Error;
use std::path::PathBuf;
use code_producers::c_elements::IODef;
use code_producers::components::TemplateInstanceIOMap;
use compiler::circuit_design::function::FunctionCode;
use lazy_static::lazy_static;
use type_analysis::check_types::check_types;
use circom_witnesscalc::{deserialize_inputs, InputSignalsInfo};
use circom_witnesscalc::graph::{optimize, Node, Operation, UnoOperation, TresOperation, Nodes, NodeConstErr, NodeIdx};

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

// if instruction pointer is a store to the signal, return the signal index
// and the src instruction to store to the signal
fn try_signal_store<'a>(
    inst: &'a InstructionPointer,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Option<(usize, &'a InstructionPointer)> {
    let store_bucket = match **inst {
        Instruction::Store(ref store_bucket) => store_bucket,
        _ => return None,
    };
    if let AddressType::Signal = store_bucket.dest_address_type {} else { return None; };
    match &store_bucket.dest {
        LocationRule::Indexed {
            location,
            template_header,
        } => {
            if template_header.is_some() {
                panic!("not implemented: template_header expected to be None");
            }
            let signal_idx =
                calc_expression(
                    location, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
                .must_const_usize(nodes, call_stack);

            let signal_idx = component_signal_start + signal_idx;
            Some((signal_idx, &store_bucket.src))
        }
        LocationRule::Mapped { .. } => {
            todo!()
        }
    }
}

fn var_from_value_instruction_n(
    value_bucket: &ValueBucket, nodes: &Nodes, n: usize,
    call_stack: &Vec<String>) -> Vec<Var> {

    match value_bucket.parse_as {
        ValueType::BigInt => {
            let mut result = Vec::with_capacity(n);

            for i in 0..n {
                assert!(
                    matches!(
                        nodes.get(NodeIdx(value_bucket.value+i)),
                        Some(Node::Constant(..))),
                    "node #{} expected to be a constant, but it is not; {}",
                    value_bucket.value+i, call_stack.join(" -> "));
                result.push(Var::Node(value_bucket.value+i));
            };

            result
        },
        ValueType::U32 => {
            assert_eq!(n, 1,
                "for ValueType::U32 number of values is expected to be 1; {}",
                call_stack.join(" -> "));
            vec![Var::Value(U256::from(value_bucket.value))]
        },
    }
}

fn operator_argument_instruction_n(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    subcomponents: &Vec<Option<ComponentInstance>>,
    size: usize,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Vec<usize> {
    assert!(size > 0, "size = {}", size);

    if size == 1 {
        // operator_argument_instruction implements much more cases than
        // this function, so we can use it here is size == 1
        return vec![operator_argument_instruction(
            inst, nodes, signal_node_idx, vars,
            component_signal_start, subcomponents, io_map, print_debug,
            call_stack)];
    }

    match **inst {
        Instruction::Load(ref load_bucket) => {
            match load_bucket.address_type {
                AddressType::Signal => match &load_bucket.src {
                    LocationRule::Indexed {
                        location,
                        template_header,
                    } => {
                        if template_header.is_some() {
                            panic!("not implemented: template_header expected to be None");
                        }
                        let signal_idx =
                            calc_expression(
                                location, nodes, vars, component_signal_start,
                                signal_node_idx, subcomponents, io_map,
                                print_debug, call_stack)
                            .must_const_usize(nodes, call_stack);
                        let mut result = Vec::with_capacity(size);
                        for i in 0..size {
                            let signal_node = signal_node_idx[component_signal_start + signal_idx + i];
                            assert_ne!(
                                signal_node, usize::MAX,
                                "signal {}/{}/{} is not set yet",
                                component_signal_start, signal_idx, i);
                            result.push(signal_node);
                        }
                        return result;
                    }
                    LocationRule::Mapped { .. } => {
                        todo!()
                    }
                },
                AddressType::SubcmpSignal { ref cmp_address, .. } => {
                    let subcomponent_idx =
                        calc_expression(
                            cmp_address, nodes, vars, component_signal_start,
                            signal_node_idx, subcomponents, io_map, print_debug,
                            call_stack)
                        .must_const_usize(nodes, call_stack);

                    let (signal_idx, template_header) = match load_bucket.src {
                        LocationRule::Indexed {
                            ref location,
                            ref template_header,
                        } => {
                            let signal_idx = calc_expression(
                                location, nodes, vars, component_signal_start,
                                signal_node_idx, subcomponents, io_map,
                                print_debug, call_stack);
                            let signal_idx = signal_idx.to_const_usize(nodes)
                                .unwrap_or_else(|e| panic!(
                                    "can't calculate const usize signal index: {}: {}",
                                    e, call_stack.join(" -> ")));
                            (signal_idx,
                             template_header.as_ref().unwrap_or(&"-".to_string()).clone())
                        }
                        LocationRule::Mapped { ref signal_code, ref indexes } => {
                            calc_mapped_signal_idx(
                                subcomponents, subcomponent_idx, io_map,
                                signal_code.clone(), indexes, nodes, vars,
                                component_signal_start, signal_node_idx,
                                print_debug, call_stack)
                        }
                    };
                    let signal_offset = subcomponents[subcomponent_idx]
                        .as_ref()
                        .unwrap()
                        .signal_offset;

                    if print_debug {
                        let location_rule = match load_bucket.src {
                            LocationRule::Indexed { .. } => "Indexed",
                            LocationRule::Mapped { .. } => "Mapped",
                        };
                        println!(
                            "Load subcomponent signal (location: {}, template: {}, subcomponent idx: {}, size: {}): {} + {} = {}",
                            location_rule, template_header, subcomponent_idx, size,
                            signal_offset, signal_idx, signal_offset + signal_idx);
                    }

                    let signal_idx = signal_offset + signal_idx;

                    let mut result = Vec::with_capacity(size);
                    for i in 0..size {
                        let signal_node = signal_node_idx[signal_idx + i];
                        assert_ne!(
                            signal_node, usize::MAX,
                            "signal {}/{}/{} is not set yet",
                            component_signal_start, signal_idx, i);
                        result.push(signal_node);
                    }
                    result
                }
                AddressType::Variable => {
                    let location = match load_bucket.src {
                        LocationRule::Indexed { ref location, .. } => location,
                        LocationRule::Mapped { .. } => {
                            panic!("mapped signals are supported on for subcmp signals");
                        }
                    };
                    let var_idx =
                        calc_expression(
                            location, nodes, vars, component_signal_start,
                            signal_node_idx, subcomponents, io_map, print_debug,
                            call_stack)
                        .must_const_usize(nodes, call_stack);
                    let mut result = Vec::with_capacity(size);
                    for i in 0..size {
                        match vars[var_idx+i] {
                            Some(Var::Node(idx)) => {
                                result.push(idx);
                            },
                            Some(Var::Value(ref v)) => {
                                result.push(
                                    nodes.push(Node::Constant(v.clone())).0);
                            }
                            None => { panic!("variable is not set: {}, {:?}",
                                             load_bucket.line, call_stack); }
                        };
                    }
                    result
                }
            }
        }
        _ => {
            panic!("multi-operator is not implemented for instruction: {}", inst.to_string());
        }
    }
}


fn operator_argument_instruction(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> usize {
    match **inst {
        Instruction::Load(ref load_bucket) => {
            match load_bucket.address_type {
                AddressType::Signal => match &load_bucket.src {
                    LocationRule::Indexed {
                        location,
                        template_header,
                    } => {
                        if template_header.is_some() {
                            panic!("not implemented: template_header expected to be None");
                        }
                        let signal_idx =
                            calc_expression(
                                location, nodes, vars, component_signal_start,
                                signal_node_idx, subcomponents, io_map,
                                print_debug, call_stack)
                            .must_const_usize(nodes, call_stack);
                        let signal_idx = component_signal_start + signal_idx;
                        let signal_node = signal_node_idx[signal_idx];
                        assert_ne!(signal_node, usize::MAX, "signal is not set yet");
                        return signal_node;
                    }
                    LocationRule::Mapped { .. } => {
                        todo!()
                    }
                },
                AddressType::SubcmpSignal {
                    ref cmp_address, ..
                } => {
                    let subcomponent_idx =
                        calc_expression(
                            cmp_address, nodes, vars, component_signal_start,
                            signal_node_idx, subcomponents, io_map, print_debug,
                            call_stack)
                        .must_const_usize(nodes, call_stack);

                    let (signal_idx, template_header) = match load_bucket.src {
                        LocationRule::Indexed {
                            ref location,
                            ref template_header,
                        } => {
                            let signal_idx =
                                calc_expression(
                                    location, nodes, vars,
                                    component_signal_start, signal_node_idx,
                                    subcomponents, io_map, print_debug,
                                    call_stack)
                                .must_const_usize(nodes, call_stack);
                            (signal_idx,
                             template_header.as_ref().unwrap_or(&"-".to_string()).clone())
                        }
                        LocationRule::Mapped { ref signal_code, ref indexes } => {
                            calc_mapped_signal_idx(
                                subcomponents, subcomponent_idx, io_map,
                                signal_code.clone(), indexes, nodes, vars,
                                component_signal_start, signal_node_idx,
                                print_debug, call_stack)
                        }
                    };

                    let signal_offset = subcomponents[subcomponent_idx]
                        .as_ref().unwrap().signal_offset;

                    if print_debug {
                        println!(
                            "Load subcomponent signal: ({}) [{}] {} + {} = {}",
                            template_header, subcomponent_idx, signal_offset,
                            signal_idx, signal_offset + signal_idx);
                    }

                    let signal_idx = signal_offset + signal_idx;
                    let signal_node = signal_node_idx[signal_idx];
                    assert_ne!(signal_node, usize::MAX, "signal is not set yet");
                    return signal_node;
                }
                AddressType::Variable => {
                    match load_bucket.src {
                        LocationRule::Indexed { ref location, .. } => {
                            let var_idx =
                                calc_expression(
                                    location, nodes, vars,
                                    component_signal_start, signal_node_idx,
                                    subcomponents, io_map, print_debug,
                                    call_stack)
                                .must_const_usize(nodes, call_stack);
                            match vars[var_idx] {
                                Some(Var::Node(idx)) => idx,
                                Some(Var::Value(ref v)) => {
                                    nodes.push(Node::Constant(v.clone())).0
                                }
                                None => { panic!("variable is not set"); }
                            }
                        }
                        LocationRule::Mapped { .. } => {
                            todo!()
                        }
                    }
                }
            }
        }
        Instruction::Compute(ref compute_bucket) => {
            let node = node_from_compute_bucket(
                compute_bucket, nodes, signal_node_idx, vars,
                component_signal_start, subcomponents, io_map, print_debug,
                call_stack);
            nodes.push(node).0
        }
        Instruction::Value(ref value_bucket) => {
            match value_bucket.parse_as {
                ValueType::BigInt => match nodes.get(NodeIdx(value_bucket.value)) {
                    Some(Node::Constant(..)) => {
                        value_bucket.value
                    }
                    _ => {
                        panic!("there is expected to be constant node");
                    }
                },
                ValueType::U32 => {
                    // in case it is a valid case, maybe we can make a
                    // constant, add it to nodes and return its index
                    panic!("not implemented");
                }
            }
        }
        _ => {
            panic!("not implemented for instruction: {}", inst.to_string());
        }
    }
}

lazy_static! {
    static ref DUO_OPERATORS_MAP: HashMap<OperatorType, Operation> = {
        let mut m = HashMap::new();
        m.insert(OperatorType::Mul, Operation::Mul);
        m.insert(OperatorType::Div, Operation::Div);
        m.insert(OperatorType::Add, Operation::Add);
        m.insert(OperatorType::Sub, Operation::Sub);
        m.insert(OperatorType::Pow, Operation::Pow);
        m.insert(OperatorType::IntDiv, Operation::Idiv);
        m.insert(OperatorType::Mod, Operation::Mod);
        m.insert(OperatorType::ShiftL, Operation::Shl);
        m.insert(OperatorType::ShiftR, Operation::Shr);
        m.insert(OperatorType::LesserEq, Operation::Leq);
        m.insert(OperatorType::GreaterEq, Operation::Geq);
        m.insert(OperatorType::Lesser, Operation::Lt);
        m.insert(OperatorType::Greater, Operation::Gt);
        m.insert(OperatorType::Eq(1), Operation::Eq);
        m.insert(OperatorType::NotEq, Operation::Neq);
        m.insert(OperatorType::BoolAnd, Operation::Land);
        m.insert(OperatorType::BitOr, Operation::Bor);
        m.insert(OperatorType::BitAnd, Operation::Band);
        m.insert(OperatorType::BitXor, Operation::Bxor);
        m.insert(OperatorType::MulAddress, Operation::Mul);
        m.insert(OperatorType::AddAddress, Operation::Add);
        m
    };
    static ref UNO_OPERATORS_MAP: HashMap<OperatorType, UnoOperation> = {
        let mut m = HashMap::new();
        m.insert(OperatorType::PrefixSub, UnoOperation::Neg);
        m.insert(OperatorType::ToAddress, UnoOperation::Id);
        m
    };
}

fn node_from_compute_bucket(
    compute_bucket: &ComputeBucket,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Node {
    if let Some(op) = DUO_OPERATORS_MAP.get(&compute_bucket.op) {
        let arg1 = operator_argument_instruction(
            &compute_bucket.stack[0], nodes, signal_node_idx, vars,
            component_signal_start, subcomponents, io_map, print_debug,
            call_stack);
        let arg2 = operator_argument_instruction(
            &compute_bucket.stack[1], nodes, signal_node_idx, vars,
            component_signal_start, subcomponents, io_map, print_debug,
            call_stack);
        return Node::Op(op.clone(), arg1, arg2);
    }
    if let Some(op) = UNO_OPERATORS_MAP.get(&compute_bucket.op) {
        let arg1 = operator_argument_instruction(
            &compute_bucket.stack[0], nodes, signal_node_idx, vars,
            component_signal_start, subcomponents, io_map, print_debug,
            call_stack);
        return Node::UnoOp(op.clone(), arg1);
    }
    panic!(
        "not implemented: this operator is not supported to be converted to Node: {}",
        compute_bucket.to_string());
}

fn calc_mapped_signal_idx(
    subcomponents: &Vec<Option<ComponentInstance>>,
    subcomponent_idx: usize, io_map: &TemplateInstanceIOMap, signal_code: usize,
    indexes: &Vec<InstructionPointer>, nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>, component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>, print_debug: bool,
    call_stack: &Vec<String>) -> (usize, String) {

    let template_id = &subcomponents[subcomponent_idx].as_ref().unwrap().template_id;
    let signals = io_map.get(template_id).unwrap();
    let template_def = format!("<template id: {}>", template_id);
    let def: &IODef = &signals[signal_code];
    let mut map_access = def.offset;

    if indexes.len() > 0 {
        if indexes.len() > 1 {
            todo!("not implemented yet");
        }
        let map_index = calc_expression(
            &indexes[0], nodes, vars, component_signal_start,
            signal_node_idx, subcomponents, io_map, print_debug, call_stack);
        let map_index = map_index.must_const_usize(nodes, call_stack);
        map_access += map_index;
    }

    (map_access, template_def)
}

fn process_instruction(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    vars: &mut Vec<Option<Var>>,
    subcomponents: &mut Vec<Option<ComponentInstance>>,
    templates: &Vec<TemplateCode>,
    functions: &Vec<FunctionCode>,
    component_signal_start: usize,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) {
    match **inst {
        Instruction::Value(..) => {
            panic!("not implemented");
        }
        Instruction::Load(..) => {
            panic!("not implemented");
        }
        Instruction::Store(ref store_bucket) => {
            match store_bucket.dest_address_type {
                AddressType::Signal => {
                    match &store_bucket.dest {
                        LocationRule::Indexed {
                            location,
                            template_header,
                        } => {
                            if template_header.is_some() {
                                panic!("not implemented: template_header expected to be None");
                            }
                            let signal_idx =
                                calc_expression(
                                    location, nodes, vars,
                                    component_signal_start, signal_node_idx,
                                    subcomponents, io_map, print_debug,
                                    call_stack)
                                .must_const_usize(nodes, call_stack);

                            if print_debug {
                                println!(
                                    "Store signal at offset {} + {} = {}",
                                    component_signal_start, signal_idx,
                                    component_signal_start + signal_idx);
                            }
                            let signal_idx = component_signal_start + signal_idx;

                            let node_idxs = operator_argument_instruction_n(
                                &store_bucket.src, nodes, signal_node_idx, vars,
                                component_signal_start, subcomponents,
                                store_bucket.context.size, io_map, print_debug,
                                call_stack);

                            assert_eq!(node_idxs.len(), store_bucket.context.size);

                            for i in 0..store_bucket.context.size {
                                if signal_node_idx[signal_idx + i] != usize::MAX {
                                    panic!("signal is already set");
                                }
                                signal_node_idx[signal_idx + i] = node_idxs[i];
                            }
                        }
                        // LocationRule::Mapped { signal_code, indexes } => {}
                        _ => {
                            panic!(
                                "not implemented: store destination support only Indexed type: {}",
                                store_bucket.dest.to_string()
                            );
                        }
                    }
                }
                AddressType::Variable => {
                    match &store_bucket.dest {
                        LocationRule::Indexed {
                            location,
                            template_header,
                        } => {
                            if template_header.is_some() {
                                panic!("not implemented: template_header expected to be None");
                            }
                            let lvar_idx =
                                calc_expression(
                                    location, nodes, vars,
                                    component_signal_start, signal_node_idx,
                                    subcomponents, io_map, print_debug,
                                    call_stack)
                                .must_const_usize(nodes, call_stack);
                            let var_exprs = calc_expression_n(
                                &store_bucket.src, nodes, vars,
                                component_signal_start, signal_node_idx,
                                subcomponents, store_bucket.context.size,
                                io_map, print_debug, call_stack);
                            for i in 0..store_bucket.context.size {
                                vars[lvar_idx + i] = Some(var_exprs[i].clone());
                            }
                        }
                        LocationRule::Mapped {..} => {
                            panic!("mapped location is not supported for AddressType::Variable");
                        }
                    }
                }
                AddressType::SubcmpSignal {
                    ref cmp_address,
                    ref input_information,
                    ..
                } => {
                    let node_idxs = operator_argument_instruction_n(
                        &store_bucket.src, nodes, signal_node_idx, vars,
                        component_signal_start, subcomponents,
                        store_bucket.context.size, io_map, print_debug,
                        call_stack);
                    assert_eq!(node_idxs.len(), store_bucket.context.size);

                    store_subcomponent_signals(
                        cmp_address, input_information, nodes, vars,
                        component_signal_start, signal_node_idx, subcomponents,
                        io_map, &node_idxs, &store_bucket.dest,
                        store_bucket.context.size, templates, functions,
                        print_debug, call_stack);
                }
            };
        }
        Instruction::Compute(_) => {
            panic!("not implemented");
        }
        Instruction::Call(ref call_bucket) => {
            let mut fn_vars: Vec<Option<Var>> = vec![None; call_bucket.arena_size];

            let mut idx = 0;
            let mut count: usize = 0;
            for inst2 in &call_bucket.arguments {
                let args = calc_expression_n(
                    inst2, nodes, vars, component_signal_start, signal_node_idx,
                    subcomponents, call_bucket.argument_types[idx].size,
                    io_map, print_debug, call_stack);
                for arg in args {
                    fn_vars[count] = Some(arg);
                    count += 1;
                }
                idx += 1;
            }

            let r = run_function(
                call_bucket, functions, &mut fn_vars, nodes, print_debug,
                call_stack);

            match call_bucket.return_info {
                ReturnType::Intermediate{ ..} => { todo!(); }
                ReturnType::Final( ref final_data ) => {
                    if let FnReturn::FnVar {ln, ..} = r {
                        assert!(final_data.context.size >= ln);
                    }
                    // assert_eq!(final_data.context.size, r.ln);
                    store_function_return_results(
                        final_data, &fn_vars, &r, vars, nodes,
                        component_signal_start, signal_node_idx,
                        subcomponents, io_map, templates, functions,
                        print_debug, call_stack);
                }
            }
        }
        Instruction::Branch(ref branch_bucket) => {
            let cond = calc_expression(
                &branch_bucket.cond, nodes, vars, component_signal_start,
                signal_node_idx, subcomponents, io_map, print_debug,
                call_stack);
            match cond.to_const(nodes) {
                Ok(cond_val) => {
                    let inst_list = if cond_val == U256::ZERO {
                        &branch_bucket.else_branch
                    } else {
                        &branch_bucket.if_branch
                    };
                    for inst in inst_list {
                        process_instruction(
                            inst, nodes, signal_node_idx, vars, subcomponents,
                            templates, functions, component_signal_start,
                            io_map, print_debug, call_stack);
                    }
                }
                Err(NodeConstErr::InputSignal) => {
                    // If we have this error, then condition is a node
                    // that depends on input signal
                    let node_idx = if let Var::Node(node_idx) = cond {
                        node_idx
                    } else {
                        panic!("[assertion] expected to have a node with ternary operation here");
                    };

                    if branch_bucket.if_branch.len() != 1 || branch_bucket.else_branch.len() != 1 {
                        panic!("Non-constant condition may be used only in ternary operation and both branches of code must be of length 1");
                    }
                    let if_branch = try_signal_store(
                        &branch_bucket.if_branch[0], nodes, vars,
                        component_signal_start, signal_node_idx, subcomponents,
                        io_map, print_debug, call_stack);
                    let else_branch = try_signal_store(
                        &branch_bucket.else_branch[0], nodes, vars,
                        component_signal_start, signal_node_idx, subcomponents,
                        io_map, print_debug, call_stack);
                    match (if_branch, else_branch) {
                        (Some((if_signal_idx, if_src)), Some((else_signal_idx, else_src))) => {
                            if if_signal_idx != else_signal_idx {
                                panic!("if and else branches must store to the same signal");
                            }

                            assert_eq!(
                                signal_node_idx[if_signal_idx],
                                usize::MAX,
                                "signal already set"
                            );

                            let node_idx_if = operator_argument_instruction(
                                if_src, nodes, signal_node_idx, vars,
                                component_signal_start, subcomponents, io_map,
                                print_debug, call_stack);

                            let node_idx_else = operator_argument_instruction(
                                else_src, nodes, signal_node_idx, vars,
                                component_signal_start, subcomponents, io_map,
                                print_debug, call_stack);

                            let node = Node::TresOp(TresOperation::TernCond, node_idx, node_idx_if, node_idx_else);
                            signal_node_idx[if_signal_idx] = nodes.push(node).0;
                        }
                        _ => {
                            panic!(
                                "if branch or else branch is not a store to the signal, which is the only option for ternary operation\n{}\nIF: {}\nELSE: {}",
                                call_stack.join(" -> "),
                                branch_bucket.if_branch[0].to_string(),
                                branch_bucket.else_branch[0].to_string());
                        }
                    }
                }
                Err(e) => {
                    panic!(
                        "unexpected condition error: {}: {}",
                        e, call_stack.join(" -> "));
                }
            }
        }
        Instruction::Return(_) => {
            panic!("not implemented");
        }
        Instruction::Assert(_) => {
            // asserts are not supported in witness graph
            // panic!("not implemented");
        }
        Instruction::Log(_) => {
            panic!("not implemented");
        }
        Instruction::Loop(ref loop_bucket) => {
            while check_continue_condition(
                &loop_bucket.continue_condition, nodes, vars,
                component_signal_start, signal_node_idx, subcomponents,
                io_map, print_debug, call_stack) {
                for i in &loop_bucket.body {
                    process_instruction(
                        i, nodes, signal_node_idx, vars, subcomponents,
                        templates, functions, component_signal_start, io_map,
                        print_debug, call_stack);
                }
            }
        }
        Instruction::CreateCmp(ref create_component_bucket) => {
            let sub_cmp_idx =
                calc_expression(
                    &create_component_bucket.sub_cmp_id, nodes, vars,
                    component_signal_start, signal_node_idx, subcomponents,
                    io_map, print_debug, call_stack)
                .must_const_usize(nodes, call_stack);

            assert!(
                sub_cmp_idx + create_component_bucket.number_of_cmp - 1 < subcomponents.len(),
                "cmp_idx = {}, number_of_cmp = {}, subcomponents.len() = {}",
                sub_cmp_idx,
                create_component_bucket.number_of_cmp,
                subcomponents.len()
            );

            let mut cmp_signal_offset = create_component_bucket.signal_offset;

            for i in sub_cmp_idx..sub_cmp_idx + create_component_bucket.number_of_cmp {
                if let Some(_) = subcomponents[i] {
                    panic!("subcomponent already set");
                }
                subcomponents[i] = Some(ComponentInstance {
                    template_id: create_component_bucket.template_id,
                    signal_offset: component_signal_start + cmp_signal_offset,
                    number_of_inputs: templates[create_component_bucket.template_id]
                        .number_of_inputs,
                });
                cmp_signal_offset += create_component_bucket.signal_offset_jump;
            }
            if print_debug {
                println!(
                    "{}",
                    fmt_create_cmp_bucket(
                        create_component_bucket, nodes, vars,
                        component_signal_start, signal_node_idx, &subcomponents,
                        io_map, print_debug, call_stack));
            }
            if !create_component_bucket.has_inputs {
                for i in sub_cmp_idx..sub_cmp_idx + create_component_bucket.number_of_cmp {
                    run_template(
                        templates, functions,
                        subcomponents[i].as_ref().unwrap().template_id, nodes,
                        signal_node_idx,
                        subcomponents[i].as_ref().unwrap().signal_offset,
                        io_map, print_debug, call_stack)
                }
            }
        }
    }
}

fn store_function_return_results_into_variable(
    final_data: &FinalData, src_vars: &Vec<Option<Var>>, ret: &FnReturn,
    dst_vars: &mut Vec<Option<Var>>, nodes: &mut Nodes,
    call_stack: &Vec<String>) {

    assert!(matches!(final_data.dest_address_type, AddressType::Variable));

    match &final_data.dest {
        LocationRule::Indexed {
            location,
            template_header,
        } => {
            if template_header.is_some() {
                panic!("not implemented: template_header expected to be None");
            }
            let lvar_idx =
                calc_function_expression(location, dst_vars, nodes, call_stack)
                    .must_const_usize(nodes, call_stack);

            match ret {
                FnReturn::FnVar { idx, .. } => {
                    for i in 0..final_data.context.size {
                        let v = if let Some(v) = &src_vars[idx + i] {
                            v
                        } else {
                            panic!("return value is not set {} / {}", idx, i)
                        };
                        dst_vars[lvar_idx + i] = Some(v.clone());
                    }

                }
                FnReturn::Value(v) => {
                    assert_eq!(final_data.context.size, 1);
                    dst_vars[lvar_idx] = Some(v.clone());
                }
            }
        }
        LocationRule::Mapped { .. } => { todo!() }
    }
}

fn store_function_return_results_into_subsignal(
    final_data: &FinalData, src_vars: &Vec<Option<Var>>, ret: &FnReturn,
    dst_vars: &mut Vec<Option<Var>>, nodes: &mut Nodes,
    component_signal_start: usize, signal_node_idx: &mut Vec<usize>,
    subcomponents: &mut Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap, templates: &Vec<TemplateCode>,
    functions: &Vec<FunctionCode>, print_debug: bool,
    call_stack: &Vec<String>) {

    let (cmp_address, input_information) = if let AddressType::SubcmpSignal {cmp_address, input_information, ..} = &final_data.dest_address_type {
        (cmp_address, input_information)
    } else {
        panic!("expected SubcmpSignal destination address type");
    };

    let mut src_node_idxs: Vec<usize> = Vec::new();
    match ret {
        FnReturn::FnVar { idx, .. } => {
            for i in 0..final_data.context.size {
                match src_vars[idx+i] {
                    Some(Var::Node(node_idx)) => {
                        src_node_idxs.push(node_idx);
                    }
                    Some(Var::Value(v)) => {
                        src_node_idxs.push(
                            nodes.push(Node::Constant(v.clone())).0);
                    }
                    None => {
                        panic!("variable at index {} is not set", i);
                    }
                }
            }

        }
        FnReturn::Value(v) => {
            assert_eq!(final_data.context.size, 1);
            match v {
                Var::Node(node_idx) => {
                    src_node_idxs.push(node_idx.clone());
                }
                Var::Value(v) => {
                    src_node_idxs.push(nodes.push(Node::Constant(v.clone())).0);
                }
            }
        }
    }

    store_subcomponent_signals(
        cmp_address, input_information, nodes, dst_vars, component_signal_start,
        signal_node_idx, subcomponents, io_map, &src_node_idxs, &final_data.dest,
        final_data.context.size, templates, functions, print_debug, call_stack);
}

fn store_function_return_results(
    final_data: &FinalData, src_vars: &Vec<Option<Var>>, ret: &FnReturn,
    dst_vars: &mut Vec<Option<Var>>, nodes: &mut Nodes,
    component_signal_start: usize, signal_node_idx: &mut Vec<usize>,
    subcomponents: &mut Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap, templates: &Vec<TemplateCode>,
    functions: &Vec<FunctionCode>, print_debug: bool,
    call_stack: &Vec<String>) {

    match &final_data.dest_address_type {
        AddressType::Signal => todo!("Signal"),
        AddressType::Variable => {
            store_function_return_results_into_variable(
                final_data, src_vars, ret, dst_vars, nodes, call_stack);
        }
        AddressType::SubcmpSignal {..} => {
            store_function_return_results_into_subsignal(
                final_data, src_vars, ret, dst_vars, nodes,
                component_signal_start, signal_node_idx, subcomponents,
                io_map, templates, functions, print_debug, call_stack);
        }
    }
}

fn run_function(
    call_bucket: &CallBucket, functions: &Vec<FunctionCode>,
    fn_vars: &mut Vec<Option<Var>>, nodes: &mut Nodes,
    print_debug: bool, call_stack: &Vec<String>) -> FnReturn {

    // for i in functions {
    //     println!("Function: {} {}", i.header, i.name);
    // }

    let f = find_function(&call_bucket.symbol, functions);
    if print_debug {
        println!("Run function {}", &call_bucket.symbol);
    }

    let mut call_stack = call_stack.clone();
    call_stack.push(f.name.clone());

    let mut r: Option<FnReturn> = None;
    for i in &f.body {
        r = process_function_instruction(
            i, fn_vars, nodes, functions, print_debug, &call_stack);
        if r.is_some() {
            break;
        }
    }
    // println!("{}", f.to_string());

    let r = r.expect("no return found");
    if print_debug {
        println!("Function {} returned", &call_bucket.symbol);
    }
    r
}
fn calc_function_expression_n(
    inst: &InstructionPointer, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, n: usize, call_stack: &Vec<String>) -> Vec<Var> {

    if n == 1 {
        let v = calc_function_expression(inst, fn_vars, nodes, call_stack);
        return vec![v];
    }

    match **inst {
        Instruction::Value(ref value_bucket) => {
            var_from_value_instruction_n(value_bucket, nodes, n, call_stack)
        }
        Instruction::Load(ref load_bucket) => {
            match load_bucket.address_type {
                AddressType::Variable => match load_bucket.src {
                    LocationRule::Indexed {
                        ref location,
                        ref template_header,
                    } => {
                        if template_header.is_some() {
                            panic!("not implemented: template_header expected to be None");
                        }
                        let var_idx = calc_function_expression(
                            location, fn_vars, nodes, call_stack);
                        let var_idx = var_idx.must_const_usize(
                            nodes, call_stack);
                        let mut result = Vec::with_capacity(n);
                        for i in 0..n {
                            result.push(match fn_vars[var_idx+i] {
                                Some(ref v) => v.clone(),
                                None => panic!("variable is not set yet"),
                            });
                        };
                        result
                    }
                    LocationRule::Mapped { .. } => {
                        todo!()
                    }
                },
                _ => {
                    panic!("not implemented for a function: {}", load_bucket.to_string());
                }
            }
        }
        _ => {
            panic!("not implemented: {}", inst.to_string())
        }
    }
}

fn calc_function_expression(
    inst: &InstructionPointer, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> Var {

    match **inst {
        Instruction::Value(ref value_bucket) => {
            match value_bucket.parse_as {
                ValueType::BigInt => match nodes.get(NodeIdx(value_bucket.value)) {
                    Some(Node::Constant(..)) => Var::Node(value_bucket.value),
                    _ => panic!("not a constant"),
                },
                ValueType::U32 => Var::Value(U256::from(value_bucket.value)),
            }
        }
        Instruction::Load(ref load_bucket) => {
            match load_bucket.address_type {
                AddressType::Variable => match load_bucket.src {
                    LocationRule::Indexed {
                        ref location,
                        ref template_header,
                    } => {
                        if template_header.is_some() {
                            panic!("not implemented: template_header expected to be None");
                        }
                        let var_idx = calc_function_expression(
                            location, fn_vars, nodes, call_stack);
                        let var_idx = var_idx.to_const_usize(nodes)
                            .unwrap_or_else(|e| {
                                panic!("expected constant value: {}: {}",
                                       e, call_stack.join(" -> "));
                            });
                        match fn_vars[var_idx] {
                            Some(ref v) => v.clone(),
                            None => panic!("variable is not set yet"),
                        }
                    }
                    LocationRule::Mapped { .. } => {
                        todo!()
                    }
                },
                _ => {
                    panic!("not implemented for function: {}", load_bucket.to_string());
                }
            }
        }
        Instruction::Compute(ref compute_bucket) => {
            compute_function_expression(
                compute_bucket, fn_vars, nodes, call_stack)
        },
        _ => {
            panic!("not implemented: {}", inst.to_string())
        }
    }
}

fn node_from_var(v: &Var, nodes: &mut Nodes) -> usize {
    match v {
        Var::Value(ref v) => {
            nodes.push(Node::Constant(v.clone())).0
        }
        Var::Node(node_idx) => *node_idx,
    }
}

fn compute_function_expression(
    compute_bucket: &ComputeBucket, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> Var {

    if let Some(op) = DUO_OPERATORS_MAP.get(&compute_bucket.op) {
        assert_eq!(compute_bucket.stack.len(), 2);
        let a = calc_function_expression(
            compute_bucket.stack.get(0).unwrap(), fn_vars,
            nodes, call_stack);
        let b = calc_function_expression(
            compute_bucket.stack.get(1).unwrap(), fn_vars,
            nodes, call_stack);
        match (&a, &b) {
            (Var::Value(a), Var::Value(b)) => {
                return Var::Value(op.eval(a.clone(), b.clone()));
            }
            _ => {
                let a_idx = node_from_var(&a, nodes);
                let b_idx = node_from_var(&b, nodes);
                return Var::Node(nodes.push(Node::Op(op.clone(), a_idx, b_idx)).0);
            }
        }
    }

    if let Some(op) = UNO_OPERATORS_MAP.get(&compute_bucket.op) {
        assert_eq!(compute_bucket.stack.len(), 1);
        let a = calc_function_expression(
            compute_bucket.stack.get(0).unwrap(), fn_vars,
            nodes, call_stack);
        match &a {
            Var::Value(v) => {
                return Var::Value(op.eval(v.clone()));
            }
            Var::Node(node_idx) => {
                return Var::Node(nodes.push(Node::UnoOp(op.clone(), *node_idx)).0);
            }
        }
    }

    panic!(
        "unsupported operator: {}: {}",
        compute_bucket.op.to_string(), call_stack.join(" -> "));
}

enum FnReturn {
    FnVar{idx: usize, ln: usize},
    Value(Var),
}

fn build_return(
    return_bucket: &ReturnBucket, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> FnReturn {

    match *return_bucket.value {
        Instruction::Load(ref load_bucket) => {
            FnReturn::FnVar {
                idx: calc_return_load_idx(
                    load_bucket, fn_vars, nodes, call_stack),
                ln: return_bucket.with_size,
            }
        }
        Instruction::Compute(ref compute_bucket) => {
            let v = compute_function_expression(
                compute_bucket, fn_vars, nodes, call_stack);
            FnReturn::Value(v)
        }
        Instruction::Value(ref value_bucket) => {
            let mut vars = var_from_value_instruction_n(
                value_bucket, nodes, 1, call_stack);
            assert_eq!(vars.len(), 1, "expected one result value");
            FnReturn::Value(vars.pop().unwrap())
        }
        _ => {
            panic!("unexpected instruction for return statement: {}",
                   return_bucket.value.to_string());
        }
    }
}

fn calc_return_load_idx(
    load_bucket: &LoadBucket, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> usize {

    match &load_bucket.address_type {
        AddressType::Variable => {}, // OK
        _ => {
            panic!("expected the return statement support only variable address type");
        }
    }
    let ip = if let LocationRule::Indexed { location, .. } = &load_bucket.src {
        location
    } else {
        panic!("not implemented: location rule supposed to be Indexed");
    };
    let idx = calc_function_expression(ip, fn_vars, nodes, call_stack);
    idx.must_const_usize(nodes, call_stack)
}

// return variable value and it's index
fn store_function_variable(
    store_bucket: &StoreBucket, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> (Var, usize) {

    assert!(matches!(store_bucket.dest_address_type, AddressType::Variable),
            "functions can store only inside variables: dest_address_type: {}",
            store_bucket.dest_address_type.to_string());

    let (location, template_header) = match &store_bucket.dest {
        LocationRule::Indexed {
            location,
            template_header,
        } => {
            (location, template_header)
        }
        LocationRule::Mapped { .. } => {
            panic!("location rule supposed to be Indexed for variables");
        }
    };

    let lvar_idx =
        calc_function_expression(
            location, fn_vars, nodes, call_stack)
        .must_const_usize(nodes, call_stack);

    assert_eq!(
        store_bucket.context.size, 1,
        "variable size in ternary expression must be 1: {}, {}",
        template_header.as_ref().unwrap_or(&"-".to_string()),
        call_stack.join(" -> "));

    let v = calc_function_expression(
        &store_bucket.src, fn_vars, nodes, call_stack);

    (v, lvar_idx)
}

fn process_function_instruction(
    inst: &InstructionPointer, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, functions: &Vec<FunctionCode>,
    print_debug: bool, call_stack: &Vec<String>) -> Option<FnReturn> {

    match **inst {
        Instruction::Store(ref store_bucket) => {
            // println!("store bucket: {}", store_bucket.to_string());
            match store_bucket.dest_address_type {
                AddressType::Variable => {
                    match &store_bucket.dest {
                        LocationRule::Indexed {
                            location,
                            template_header,
                        } => {
                            if template_header.is_some() {
                                panic!("not implemented: template_header expected to be None");
                            }
                            let lvar_idx =
                                calc_function_expression(
                                    location, fn_vars, nodes, call_stack)
                                .must_const_usize(nodes, call_stack);
                            if store_bucket.context.size == 1 {
                                fn_vars[lvar_idx] = Some(calc_function_expression(
                                    &store_bucket.src, fn_vars, nodes,
                                    call_stack));
                            } else {
                                let values = calc_function_expression_n(
                                    &store_bucket.src, fn_vars, nodes,
                                    store_bucket.context.size, call_stack);
                                assert_eq!(values.len(), store_bucket.context.size);
                                for i in 0..store_bucket.context.size {
                                    fn_vars[lvar_idx + i] = Some(values[i].clone());
                                }
                            }
                            None
                        }
                        LocationRule::Mapped {..} => {
                            panic!("mapped location is not supported");
                        }
                    }
                }
                _ => {panic!("not a variable store inside a function")}
            }
        }
        Instruction::Branch(ref branch_bucket) => {
            // println!("branch bucket: {}", branch_bucket.to_string());

            let cond = calc_function_expression(
                &branch_bucket.cond, fn_vars, nodes, call_stack);
            let cond_const = cond.to_const(nodes);

            match cond_const {
                Ok(cond_const) => { // condition expression is static
                    let branch = if cond_const.gt(&U256::ZERO) {
                        &branch_bucket.if_branch
                    } else {
                        &branch_bucket.else_branch
                    };
                    for i in branch {
                        let r = process_function_instruction(
                            i, fn_vars, nodes, functions, print_debug, call_stack);
                        if r.is_some() {
                            return r;
                        }
                    }
                }
                Err(NodeConstErr::InputSignal) => { // dynamic condition expression
                    // The only supported dynamic condition is a ternary operation
                    // Both branches should be exactly one operation of
                    // storing a variable to the same signal index.
                    assert_eq!(
                        branch_bucket.if_branch.len(), 1,
                        "expected a ternary operation but it doesn't looks like one as the 'if' branch is not of length 1: {}: {}",
                        branch_bucket.else_branch.len(),
                        call_stack.join(" -> "));
                    assert_eq!(
                        branch_bucket.else_branch.len(), 1,
                        "expected a ternary operation but it doesn't looks like one as the 'else' branch is not of length 1: {}: {}",
                        branch_bucket.else_branch.len(),
                        call_stack.join(" -> "));
                    let (var_if, var_if_idx) = match *branch_bucket.if_branch[0] {
                        Instruction::Store(ref store_bucket) => {
                            store_function_variable(
                                store_bucket, fn_vars, nodes, call_stack)
                        }
                        _ => {
                            panic!(
                                "expected store operation in ternary operation of branch 'if': {}",
                                call_stack.join(" -> "));
                        }
                    };
                    let (var_else, var_else_idx) = match *branch_bucket.else_branch[0] {
                        Instruction::Store(ref store_bucket) => {
                            store_function_variable(
                                store_bucket, fn_vars, nodes, call_stack)
                        }
                        _ => {
                            panic!(
                                "expected store operation in ternary operation of branch 'else': {}",
                                call_stack.join(" -> "));
                        }
                    };
                    assert_eq!(
                        var_if_idx, var_else_idx,
                        "in ternary operation if and else branches must store to the same variable");

                    let cond_node_idx = node_from_var(&cond, nodes);
                    let if_node_idx = node_from_var(&var_if, nodes);
                    let else_node_idx = node_from_var(&var_else, nodes);
                    let tern_node_idx = nodes.push(Node::TresOp(
                        TresOperation::TernCond, cond_node_idx, if_node_idx,
                        else_node_idx));
                    fn_vars[var_if_idx] = Some(Var::Node(tern_node_idx.0));
                }
                Err(e) => {
                    panic!(
                        "error calculating function branch condition: {}: {}",
                        e, call_stack.join(" -> "));
                }
            }
            None
        }
        Instruction::Return(ref return_bucket) => {
            // println!("return bucket: {}", return_bucket.to_string());
            Some(build_return(return_bucket, fn_vars, nodes, call_stack))
        }
        Instruction::Loop(ref loop_bucket) => {
            // if call_stack.last().unwrap() == "long_div" {
            //     println!("loop: {}", loop_bucket.to_string());
            // }
            while check_continue_condition_function(
                &loop_bucket.continue_condition, fn_vars, nodes, call_stack) {

                for i in &loop_bucket.body {
                    process_function_instruction(
                        i, fn_vars, nodes, functions, print_debug, call_stack);
                }
            };
            None
        }
        Instruction::Call(ref call_bucket) => {
            let mut new_fn_vars: Vec<Option<Var>> = vec![None; call_bucket.arena_size];

            let mut idx = 0;
            let mut count: usize = 0;
            for inst2 in &call_bucket.arguments {
                let args = calc_function_expression_n(
                    inst2, fn_vars, nodes, call_bucket.argument_types[idx].size,
                    call_stack);
                for arg in args {
                    new_fn_vars[count] = Some(arg);
                    count += 1;
                }
                idx += 1;
            }

            let r = run_function(
                call_bucket, functions, &mut new_fn_vars, nodes, print_debug,
                call_stack);

            match call_bucket.return_info {
                ReturnType::Intermediate{ ..} => { todo!(); }
                ReturnType::Final( ref final_data ) => {
                    if let FnReturn::FnVar { ln, ..} = r {
                        assert!(final_data.context.size >= ln);
                    }
                    // assert_eq!(final_data.context.size, r.ln);
                    store_function_return_results_into_variable(
                        final_data, &new_fn_vars, &r, fn_vars, nodes,
                        call_stack);
                }
            };
            None
        }
        Instruction::Assert(_) => {
            // asserts are not supported in witness graph
            None
        }
        _ => {
            panic!(
                "not implemented: {}; {}",
                inst.to_string(), call_stack.join(" -> "));
        }
    }
}

fn check_continue_condition_function(
    inst: &InstructionPointer, fn_vars: &mut Vec<Option<Var>>,
    nodes: &mut Nodes, call_stack: &Vec<String>) -> bool {

    let val = calc_function_expression(inst, fn_vars, nodes, call_stack)
        .to_const(nodes)
        .unwrap_or_else(
            |e| panic!(
                "condition is not a constant: {}: {}",
                e, call_stack.join(" -> ")));

    val != U256::ZERO
}



fn find_function<'a>(name: &str, functions: &'a Vec<FunctionCode>) -> &'a FunctionCode {
    functions.iter().find(|f| f.header == name).expect("function not found")
}

#[derive(Debug, Clone)]
struct ValueTooBigError {}

impl<'a> fmt::Display for ValueTooBigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "value is too big")
    }
}

impl Error for ValueTooBigError {}

fn bigint_to_usize(value: &U256) -> Result<usize, Box<dyn Error>> {

    // Convert U256 to usize
    let bytes = value.to_le_bytes::<32>().to_vec(); // Convert to little-endian bytes
    for i in std::mem::size_of::<usize>()..bytes.len() {
        if bytes[i] != 0 {
            return Err(Box::new(ValueTooBigError {}));
        }
    }
    Ok(usize::from_le_bytes(
        bytes[..std::mem::size_of::<usize>()]
            .try_into()
            .expect("slice with incorrect length"),
    ))
}


struct ComponentInstance {
    template_id: usize,
    signal_offset: usize,
    number_of_inputs: usize,
}

fn fmt_create_cmp_bucket(
    cmp_bucket: &CreateCmpBucket,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> String {
    let sub_cmp_id = calc_expression(
        &cmp_bucket.sub_cmp_id, nodes, vars, component_signal_start,
        signal_node_idx, subcomponents, io_map, print_debug, call_stack);

    let sub_cmp_id = match sub_cmp_id {
        Var::Value(ref c) => format!("Constant {}", c.to_string()),
        Var::Node(idx) => format!("Variable {}", idx)
    };

    format!(
        r#"CreateCmpBucket: template_id: {}
                 cmp_unique_id: {}
                 symbol: {}
                 sub_cmp_id: {}
                 name_subcomponent: {}
                 defined_positions: {:?}
                 dimensions: {:?}
                 signal_offset: {}
                 signal_offset_jump: {}
                 component_offset: {}
                 component_offset_jump: {}
                 number_of_cmp: {}
                 has_inputs: {}
                 component_signal_start: {}"#,
        cmp_bucket.template_id,
        cmp_bucket.cmp_unique_id,
        cmp_bucket.symbol,
        sub_cmp_id,
        cmp_bucket.name_subcomponent,
        cmp_bucket.defined_positions,
        cmp_bucket.dimensions,
        cmp_bucket.signal_offset,
        cmp_bucket.signal_offset_jump,
        cmp_bucket.component_offset,
        cmp_bucket.component_offset_jump,
        cmp_bucket.number_of_cmp,
        cmp_bucket.has_inputs,
        component_signal_start,
    )
}

#[derive(Clone, Debug)]
enum Var {
    Value(U256),
    Node(usize),
}

impl ToString for Var {
    fn to_string(&self) -> String {
        match self {
            Var::Value(ref c) => { format!("Var::Value({})", c.to_string()) }
            Var::Node(idx) => { format!("Var::Node({})", idx) }
        }
    }
}


impl Var {
    fn to_const(&self, nodes: &Nodes) -> Result<U256, NodeConstErr> {
        match self {
            Var::Value(v) => Ok(v.clone()),
            Var::Node(node_idx) => nodes.to_const(NodeIdx::from(*node_idx)),
        }
    }

    fn to_const_usize(&self, nodes: &Nodes) -> Result<usize, Box<dyn Error>> {
        let c = self.to_const(nodes)?;
        Ok(bigint_to_usize(&c)?)
    }

    fn must_const_usize(
        &self, nodes: &Nodes, call_stack: &Vec<String>) -> usize {

        self.to_const_usize(nodes).unwrap_or_else(|e| {
            panic!("{}: {}", e, call_stack.join(" -> "));
        })
    }
}

fn load_n(
    load_bucket: &LoadBucket, nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>, component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>, size: usize,
    io_map: &TemplateInstanceIOMap, print_debug: bool,
    call_stack: &Vec<String>) -> Vec<Var> {

    match load_bucket.address_type {
        AddressType::Signal => match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header,
            } => {
                if template_header.is_some() {
                    panic!("not implemented: template_header expected to be None");
                }
                let signal_idx = calc_expression(
                    location, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack);
                let signal_idx = signal_idx.must_const_usize(
                    nodes, call_stack);
                let mut result = Vec::with_capacity(size);
                for i in 0..size {
                    let signal_idx = component_signal_start + signal_idx + i;
                    let signal_node = signal_node_idx[signal_idx];
                    assert_ne!(
                        signal_node, usize::MAX,
                        "signal {}/{}/{} is not set yet",
                        component_signal_start, signal_idx, i);
                    result.push(Var::Node(signal_node));
                }
                return result;
            }
            LocationRule::Mapped { .. } => {
                panic!("mapped signals expect only on address type SubcmpSignal");
            }
        },
        AddressType::SubcmpSignal {
            ref cmp_address, ..
        } => {
            let subcomponent_idx =
                calc_expression(
                    cmp_address, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
                .must_const_usize(nodes, call_stack);

            let (signal_idx, template_header) = match load_bucket.src {
                LocationRule::Indexed {
                    ref location,
                    ref template_header,
                } => {
                    let signal_idx = calc_expression(
                        location, nodes, vars, component_signal_start,
                        signal_node_idx, subcomponents, io_map, print_debug,
                        call_stack);
                    let signal_idx = signal_idx.to_const_usize(nodes)
                        .unwrap_or_else(|e| panic!(
                            "can't calculate signal index: {}: {}",
                            e, call_stack.join(" -> ")));
                    (signal_idx,
                     template_header.as_ref().unwrap_or(&"-".to_string()).clone())
                }
                LocationRule::Mapped { ref signal_code, ref indexes } => {
                    calc_mapped_signal_idx(
                        subcomponents, subcomponent_idx, io_map,
                        signal_code.clone(), indexes, nodes, vars,
                        component_signal_start, signal_node_idx, print_debug,
                        call_stack)
                }
            };
            let signal_offset = subcomponents[subcomponent_idx]
                .as_ref().unwrap().signal_offset;

            if print_debug {
                let location_rule = match load_bucket.src {
                    LocationRule::Indexed { .. } => "Indexed",
                    LocationRule::Mapped { .. } => "Mapped",
                };
                println!(
                    "Load subcomponent signal (location: {}, template: {}, subcomponent idx: {}, size: {}): {} + {} = {}",
                    location_rule, template_header, subcomponent_idx, size,
                    signal_offset, signal_idx, signal_offset + signal_idx);
            }

            let signal_idx = signal_offset + signal_idx;
            let mut result = Vec::with_capacity(size);
            for i in 0..size {
                let signal_node = signal_node_idx[signal_idx + i];
                assert_ne!(
                    signal_node, usize::MAX,
                    "subcomponent signal {}/{}/{} is not set yet",
                    component_signal_start, signal_idx, i);
                result.push(Var::Node(signal_node));
            }
            return result;
        }
        AddressType::Variable => {
            let location = if let LocationRule::Indexed { location, template_header } = &load_bucket.src {
                if template_header.is_some() {
                    panic!("template_header expected to be None");
                }
                location
            } else {
                panic!("location rule supposed to be Indexed for AddressType::Variable");
            };
            let var_idx =
                calc_expression(
                    location, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
                .must_const_usize(nodes, call_stack);

            let mut result: Vec<Var> = Vec::with_capacity(size);
            for i in 0..size {
                result.push(match vars[var_idx + i] {
                    Some(ref v) => v.clone(),
                    None => panic!("variable is not set yet"),
                });
            }
            result
        },
    }
}

fn build_unary_op_var(
    compute_bucket: &ComputeBucket,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Var {
    assert_eq!(compute_bucket.stack.len(), 1);
    let a = calc_expression(
        &compute_bucket.stack[0], nodes, vars, component_signal_start,
        signal_node_idx, subcomponents, io_map, print_debug, call_stack);

    match &a {
        Var::Value(ref a) => {
            Var::Value(match compute_bucket.op {
                OperatorType::ToAddress => a.clone(),
                OperatorType::PrefixSub => if a.clone() == U256::ZERO { U256::ZERO } else { M - a }
                _ => {
                    todo!(
                        "unary operator not implemented: {}",
                        compute_bucket.op.to_string()
                    );
                }
            })
        }
        Var::Node(node_idx) => {
            let node = Node::UnoOp(match compute_bucket.op {
                OperatorType::PrefixSub => UnoOperation::Neg,
                OperatorType::ToAddress => {
                    nodes.to_const(NodeIdx(*node_idx)).unwrap_or_else(|e| {
                        panic!(
                            "ToAddress argument is not a constant: {}: {}",
                            e.to_string(), call_stack.join(" -> "));
                    });
                    UnoOperation::Id
                }
                _ => {
                    todo!(
                        "operator not implemented: {}",
                        compute_bucket.op.to_string()
                    );
                }
            }, *node_idx);
            Var::Node(nodes.push(node).0)
        }
    }
}

// Create a Var from operation on two arguments a anb b
fn build_binary_op_var(
    compute_bucket: &ComputeBucket,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Var {
    assert_eq!(compute_bucket.stack.len(), 2);
    let a = calc_expression(
        &compute_bucket.stack[0], nodes, vars, component_signal_start,
        signal_node_idx, subcomponents, io_map, print_debug, call_stack);
    let b = calc_expression(
        &compute_bucket.stack[1], nodes, vars, component_signal_start,
        signal_node_idx, subcomponents, io_map, print_debug, call_stack);

    let mut node_idx = |v: &Var| match v {
        Var::Value(ref c) => {
            nodes.push(Node::Constant(c.clone())).0
        }
        Var::Node(idx) => { *idx }
    };

    match (&a, &b) {
        (Var::Value(ref a), Var::Value(ref b)) => {
            Var::Value(match compute_bucket.op {
                OperatorType::Mul => Operation::Mul.eval(a.clone(), b.clone()),
                OperatorType::Div => if b.clone() == U256::ZERO {
                    // as we are simulating a circuit execution with signals
                    // values all equal to 0, just return 0 here in case of
                    // division by zero
                    U256::ZERO
                } else {
                    a.mul_mod(b.inv_mod(M).unwrap(), M)
                },
                OperatorType::Add => a.add_mod(b.clone(), M),
                OperatorType::Sub => a.add_mod(M - b, M),
                OperatorType::Pow => Operation::Pow.eval(a.clone(), b.clone()),
                OperatorType::IntDiv => Operation::Idiv.eval(a.clone(), b.clone()),
                OperatorType::Mod => Operation::Mod.eval(a.clone(), b.clone()),
                OperatorType::ShiftL => Operation::Shl.eval(a.clone(), b.clone()),
                OperatorType::ShiftR => Operation::Shr.eval(a.clone(), b.clone()),
                OperatorType::LesserEq => Operation::Leq.eval(a.clone(), b.clone()),
                OperatorType::GreaterEq => Operation::Geq.eval(a.clone(), b.clone()),
                OperatorType::Lesser => if a < b { U256::from(1) } else { U256::ZERO }
                OperatorType::Greater => Operation::Gt.eval(a.clone(), b.clone()),
                OperatorType::Eq(1) => Operation::Eq.eval(a.clone(), b.clone()),
                OperatorType::NotEq => U256::from(a != b),
                OperatorType::BoolAnd => Operation::Land.eval(a.clone(), b.clone()),
                OperatorType::BitOr => Operation::Bor.eval(a.clone(), b.clone()),
                OperatorType::BitAnd => Operation::Band.eval(a.clone(), b.clone()),
                OperatorType::BitXor => Operation::Bxor.eval(a.clone(), b.clone()),
                OperatorType::MulAddress => a * b,
                OperatorType::AddAddress => a + b,
                _ => {
                    todo!(
                        "operator not implemented: {}",
                        compute_bucket.op.to_string()
                    );
                }
            })
        }
        _ => {
            let node = Node::Op(match compute_bucket.op {
                OperatorType::Mul => Operation::Mul,
                OperatorType::Div => Operation::Div,
                OperatorType::Add => Operation::Add,
                OperatorType::Sub => Operation::Sub,
                OperatorType::Pow => Operation::Pow,
                OperatorType::IntDiv => Operation::Idiv,
                OperatorType::Mod => Operation::Mod,
                OperatorType::ShiftL => Operation::Shl,
                OperatorType::ShiftR => Operation::Shr,
                OperatorType::LesserEq => Operation::Leq,
                OperatorType::GreaterEq => Operation::Geq,
                OperatorType::Lesser => Operation::Lt,
                OperatorType::Greater => Operation::Gt,
                OperatorType::Eq(1) => Operation::Eq,
                OperatorType::NotEq => Operation::Neq,
                OperatorType::BoolAnd => Operation::Land,
                OperatorType::BitOr => Operation::Bor,
                OperatorType::BitAnd => Operation::Band,
                OperatorType::BitXor => Operation::Bxor,
                OperatorType::MulAddress => Operation::Mul,
                OperatorType::AddAddress => Operation::Add,
                _ => {
                    todo!(
                        "operator not implemented: {}",
                        compute_bucket.op.to_string()
                    );
                }
            }, node_idx(&a), node_idx(&b));
            Var::Node(nodes.push(node).0)
        }
    }
}

// This function should calculate node based only on constant or variable
// values. Not based on signal values.
fn calc_expression(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Var {
    match **inst {
        Instruction::Value(ref value_bucket) => {
            let mut vars = var_from_value_instruction_n(
                value_bucket, nodes, 1, call_stack);
            assert_eq!(vars.len(), 1, "expected one result value");
            vars.pop().unwrap()
        }
        Instruction::Load(ref load_bucket) => {
            let r = load_n(
                load_bucket, nodes, vars, component_signal_start, signal_node_idx,
                subcomponents, 1, io_map, print_debug, call_stack);
            assert_eq!(r.len(), 1);
            r[0].clone()
        },
        Instruction::Compute(ref compute_bucket) => match compute_bucket.op {
            OperatorType::Mul | OperatorType::Div | OperatorType::Add
            | OperatorType::Sub | OperatorType::Pow | OperatorType::IntDiv
            | OperatorType::Mod | OperatorType::ShiftL | OperatorType::ShiftR
            | OperatorType::LesserEq | OperatorType::GreaterEq
            | OperatorType::Lesser | OperatorType::Greater | OperatorType::Eq(1)
            | OperatorType::NotEq | OperatorType::BoolAnd | OperatorType::BitOr
            | OperatorType::BitAnd | OperatorType::BitXor
            | OperatorType::MulAddress | OperatorType::AddAddress => {
                build_binary_op_var(
                    compute_bucket, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
            }
            OperatorType::ToAddress | OperatorType::PrefixSub => {
                build_unary_op_var(
                    compute_bucket, nodes, vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
            }
            _ => {
                todo!(
                    "operator not implemented: {}",
                    compute_bucket.op.to_string()
                );
            }
        },
        _ => {
            panic!(
                "instruction evaluation is not supported: {}",
                inst.to_string()
            );
        }
    }
}

// This function should calculate node based only on constant or variable
// values. Not based on signal values.
fn calc_expression_n(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    size: usize,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> Vec<Var> {
    if size == 1 {
        return vec![calc_expression(
            inst, nodes, vars, component_signal_start, signal_node_idx,
            subcomponents, io_map, print_debug, call_stack)];
    }

    match **inst {
        Instruction::Load(ref load_bucket) => {
            load_n(
                load_bucket, nodes, vars, component_signal_start,
                signal_node_idx, subcomponents, size, io_map, print_debug,
                call_stack)
        },
        _ => {
            panic!(
                "instruction evaluation is not supported for multiple values: {}",
                inst.to_string()
            );
        }
    }
}

fn check_continue_condition(
    inst: &InstructionPointer,
    nodes: &mut Nodes,
    vars: &mut Vec<Option<Var>>,
    component_signal_start: usize,
    signal_node_idx: &mut Vec<usize>,
    subcomponents: &Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) -> bool {
    let val = calc_expression(
            inst, nodes, vars, component_signal_start, signal_node_idx,
            subcomponents, io_map, print_debug, call_stack)
        .to_const(nodes)
        .unwrap_or_else(
            |e| panic!(
                "condition is not a constant: {}: {}",
                e, call_stack.join(" -> ")));

    val != U256::ZERO
}

fn get_constants(circuit: &Circuit) -> Vec<Node> {
    let mut constants: Vec<Node> = Vec::new();
    for c in &circuit.c_producer.field_tracking {
        constants.push(Node::Constant(U256::from_str_radix(c.as_str(), 10).unwrap()));
    }
    constants
}

fn init_input_signals(
    circuit: &Circuit,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    input_file: Option<String>,
) -> (InputSignalsInfo, Vec<U256>) {
    let input_list = circuit.c_producer.get_main_input_list();
    let mut signal_values: Vec<U256> = Vec::new();
    signal_values.push(U256::from(1));
    signal_node_idx[0] = nodes.push(Node::Input(signal_values.len() - 1)).0;
    let mut inputs_info = HashMap::new();

    let inputs: Option<HashMap<String, Vec<U256>>> = match input_file {
        Some(file) => {
            let inputs_data = fs::read(file).expect("Failed to read input file");
            let inputs = deserialize_inputs(&inputs_data).unwrap();
            Some(inputs)
        }
        None => {
            None
        }
    };

    for (name, offset, len) in input_list {
        inputs_info.insert(name.clone(), (signal_values.len(), len.clone()));
        match inputs {
            Some(ref inputs) => {
                match inputs.get(name) {
                    Some(values) => {
                        if values.len() != *len {
                            panic!(
                                "input signal {} has different length in inputs file, want {}, actual {}",
                                name, *len, values.len());
                        }
                        for (i, v) in values.iter().enumerate() {
                            signal_values.push(v.clone());
                            signal_node_idx[offset + i] = nodes.push(
                                Node::Input(signal_values.len() - 1)).0;
                        }
                    }
                    None => {
                        panic!("input signal {} is not found in inputs file", name);
                    }
                }
            }
            None => {
                for i in 0..*len {
                    signal_values.push(U256::ZERO);
                    signal_node_idx[offset + i] = nodes.push(
                        Node::Input(signal_values.len() - 1)).0;
                }
            }
        }
    }

    return (inputs_info, signal_values);
}

fn run_template(
    templates: &Vec<TemplateCode>,
    functions: &Vec<FunctionCode>,
    template_id: usize,
    nodes: &mut Nodes,
    signal_node_idx: &mut Vec<usize>,
    component_signal_start: usize,
    io_map: &TemplateInstanceIOMap,
    print_debug: bool,
    call_stack: &Vec<String>,
) {
    let tmpl = &templates[template_id];

    let tmpl_name: String = format!("{}_{}", tmpl.name, tmpl.id);
    let mut call_stack = call_stack.clone();
    call_stack.push(tmpl_name.clone());

    if print_debug {
        println!(
            "Run template {}_{}: body length: {}", tmpl.name, tmpl.id,
            tmpl.body.len());
    }

    let mut vars: Vec<Option<Var>> = vec![None; tmpl.var_stack_depth];
    let mut components: Vec<Option<ComponentInstance>> = vec![];
    for _ in 0..tmpl.number_of_components {
        components.push(None);
    }

    for inst in &tmpl.body {
        process_instruction(
            &inst, nodes, signal_node_idx, &mut vars, &mut components,
            templates, functions, component_signal_start, io_map, print_debug,
            &call_stack);
    }

    if print_debug {
        println!("Template {}_{} finished", tmpl.name, tmpl.id);
    }
    // TODO: assert all components run
}

struct Args {
    circuit_file: String,
    inputs_file: Option<String>,
    graph_file: String,
    link_libraries: Vec<PathBuf>,
    print_unoptimized: bool,
    print_debug: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    let mut circuit_file: Option<String> = None;
    let mut graph_file: Option<String> = None;
    let mut link_libraries: Vec<PathBuf> = Vec::new();
    let mut inputs_file: Option<String> = None;
    let mut print_unoptimized = false;
    let mut print_debug = false;

    let usage = |err_msg: &str| -> String {
        eprintln!("{}", err_msg);
        eprintln!("Usage: {} <circuit_file> <graph_file> [-l <link_library>]* [-i <inputs_file.json>] [-print-unoptimized] [-v]", args[0]);
        std::process::exit(1);
    };

    while i < args.len() {
        if args[i] == "-l" {
            i += 1;
            if i >= args.len() {
                usage("missing argument for -l");
            }
            link_libraries.push(args[i].clone().into());
        } else if args[i].starts_with("-l") {
            link_libraries.push(args[i][2..].to_string().into())
        } else if args[i] == "-i" {
            i += 1;
            if i >= args.len() {
                usage("missing argument for -i");
            }
            if let None = inputs_file {
                inputs_file = Some(args[i].clone());
            } else {
                usage("multiple inputs files");
            }
        } else if args[i].starts_with("-i") {
            if let None = inputs_file {
                inputs_file = Some(args[i][2..].to_string());
            } else {
                usage("multiple inputs files");
            }
        } else if args[i] == "-print-unoptimized" {
            print_unoptimized = true;
        } else if args[i] == "-v" {
            print_debug = true;
        } else if args[i].starts_with("-") {
            let message = format!("unknown argument: {}", args[i]);
            usage(&message);
        } else if let None = circuit_file {
            circuit_file = Some(args[i].clone());
        } else if let None = graph_file {
            graph_file = Some(args[i].clone());
        } else {
            usage(format!("unexpected argument: {}", args[i]).as_str());
        }
        i += 1;
    };

    Args {
        circuit_file: circuit_file.unwrap_or_else(|| { usage("missing circuit file") }),
        inputs_file,
        graph_file: graph_file.unwrap_or_else(|| { usage("missing graph file") }),
        link_libraries,
        print_unoptimized,
        print_debug,
    }
}

fn main() {
    let args = parse_args();

    let version = "2.1.9";

    let parser_result = parser::run_parser(
        args.circuit_file.clone(), version, args.link_libraries.clone());
    let mut program_archive = match parser_result {
        Err((file_library, report_collection)) => {
            Report::print_reports(&report_collection, &file_library);
            panic!("Parser error");
        }
        Ok((program_archive, warnings)) => {
            if !warnings.is_empty() {
                println!("Parser warnings:");
                for warning in warnings {
                    println!("{}", warning.get_message());
                }
            }
            program_archive
        }
    };

    match check_types(&mut program_archive) {
        Err(errs) => {
            println!("Type errors:");
            for err in errs {
                println!("{}", err.get_message());
            }
            std::process::exit(1);
        }
        Ok(warns) => {
            if !warns.is_empty() {
                println!("Type warnings:");
                for warn in warns {
                    println!("{}", warn.get_message());
                }
            }
        }
    }

    let build_config = BuildConfig {
        no_rounds: usize::MAX,
        flag_json_sub: false,
        json_substitutions: String::new(),
        flag_s: false,
        flag_f: false,
        flag_p: false,
        flag_verbose: false,
        flag_old_heuristics: false,
        inspect_constraints: false,
        prime: String::from("bn128"),
    };

    let (_, vcp) = build_circuit(program_archive, build_config).unwrap();

    let main_template_id = vcp.main_id;
    let witness_list = vcp.get_witness_list().clone();

    let circuit = run_compiler(
        vcp,
        Config {
            debug_output: true,
            produce_input_log: true,
            wat_flag: false,
        },
        version)
        .unwrap();
    println!("prime: {}", circuit.c_producer.prime);
    println!("prime_str: {}", circuit.c_producer.prime_str);
    println!("templates len: {}", circuit.templates.len());
    println!("functions len: {}", circuit.functions.len());
    println!("main header: {}", circuit.c_producer.main_header);

    let mut signal_node_idx: Vec<usize> =
        vec![usize::MAX; circuit.c_producer.total_number_of_signals];

    let mut nodes = Nodes::new();
    nodes.0.extend(get_constants(&circuit));

    let (input_signals, input_signal_values): (InputSignalsInfo, Vec<U256>) = init_input_signals(
        &circuit, &mut nodes, &mut signal_node_idx, args.inputs_file);

    // assert that template id is equal to index in templates list
    for (i, t) in circuit.templates.iter().enumerate() {
        assert_eq!(i, t.id);
        if args.print_debug {
            println!("Template #{}: {}", i, t.name);
        }
    }

    let main_component_signal_start = 1usize;
    run_template(
        &circuit.templates, &circuit.functions, main_template_id, &mut nodes,
        &mut signal_node_idx, main_component_signal_start,
        circuit.c_producer.get_io_map(), args.print_debug, &vec![]);

    for (idx, i) in signal_node_idx.iter().enumerate() {
        if *i == usize::MAX {
            println!("[warning] signal #{} is not set", idx);
        }
    }

    let mut witness_node_idxes = witness_list
        .iter().enumerate()
        .map(|(idx, i)| {
            assert_ne!(*i, usize::MAX, "signal #{} is not set", idx);
            signal_node_idx[*i]
        })
        .collect::<Vec<_>>();

    if args.print_unoptimized {
        println!("Unoptimized graph:");
        evaluate_unoptimized(&nodes, &input_signal_values, &signal_node_idx, &witness_list);
    }

    println!("number of nodes {}, signals {}", nodes.len(), witness_node_idxes.len());

    optimize(&mut nodes.0, &mut witness_node_idxes);

    println!(
        "number of nodes after optimize {}, signals {}",
        nodes.len(), witness_node_idxes.len());

    let bytes = postcard::to_stdvec(&(&nodes.0, &witness_node_idxes, &input_signals)).unwrap();
    fs::write(&args.graph_file, bytes).unwrap();

    println!("circuit graph saved to file: {}", &args.graph_file)
}

fn evaluate_unoptimized(nodes: &Nodes, inputs: &[U256], signal_node_idx: &Vec<usize>, witness_signals: &[usize]) {
    let mut node_idx_to_signal: HashMap<usize, Vec<usize>> = HashMap::new();
    for (signal_idx, &node_idx) in signal_node_idx.iter().enumerate() {
        if node_idx == usize::MAX {
            // signal was not set
            continue;
        }
        node_idx_to_signal
            .entry(node_idx)
            .and_modify(|v| v.push(signal_idx))
            .or_insert(vec![signal_idx]);
    }

    let mut signal_to_witness: HashMap<usize, Vec<usize>> = HashMap::new();
    println!("Mapping from witness index to signal index:");
    for (witness_idx, &signal_idx) in witness_signals.iter().enumerate() {
        println!("witness {} -> {}", witness_idx, signal_idx);
        signal_to_witness.entry(signal_idx).and_modify(|v| v.push(witness_idx)).or_insert(vec![witness_idx]);
    }

    let mut values = Vec::with_capacity(nodes.len());

    println!("<node idx> <value> <signal indexes> <witness indexes> <node descr>");
    for (node_idx, &node) in nodes.iter().enumerate() {
        let value = match node {
            Node::Constant(c) => c,
            Node::MontConstant(_) => { panic!("no montgomery constant expected in unoptimized graph") }
            Node::Input(i) => inputs[i],
            Node::Op(op, a, b) => op.eval(values[a], values[b]),
            Node::UnoOp(op, a) => op.eval(values[a]),
            Node::TresOp(op, a, b, c) => op.eval(values[a], values[b], values[c]),
        };
        values.push(value);

        let empty_vec: Vec<usize> = Vec::new();
        let signals_for_node: &Vec<usize> = node_idx_to_signal.get(&node_idx).unwrap_or(&empty_vec);

        let signal_idxs = signals_for_node.iter()
            .map(|&i| format!("{}_S", i))
            .collect::<Vec<String>>().join(", ");

        let mut witness_idxs: Vec<usize> = Vec::new();
        for &signal_idx in signals_for_node {
            witness_idxs.extend(signal_to_witness.get(&signal_idx).unwrap_or(&empty_vec));
        }
        let output_signals = witness_idxs.iter()
            .map(|&i| format!("{}_W", i))
            .collect::<Vec<String>>().join(", ");

        println!("[{:4}] {:>77} ({:>4}) ({:>4}) {:?}", node_idx, value.to_string(), signal_idxs, output_signals, node);
    }
}

fn store_subcomponent_signals(
    cmp_address: &InstructionPointer, input_information: &InputInformation,
    nodes: &mut Nodes, tmpl_vars: &mut Vec<Option<Var>>,
    component_signal_start: usize, signal_node_idx: &mut Vec<usize>,
    subcomponents: &mut Vec<Option<ComponentInstance>>,
    io_map: &TemplateInstanceIOMap, src_node_idxs: &Vec<usize>, dest: &LocationRule,
    size: usize, templates: &Vec<TemplateCode>, functions: &Vec<FunctionCode>,
    print_debug: bool, call_stack: &Vec<String>) {

    let input_status: &StatusInput;
    if let InputInformation::Input { ref status } = input_information {
        input_status = status;
    } else {
        panic!("incorrect input information for subcomponent signal");
    }

    let subcomponent_idx =
        calc_expression(
            cmp_address, nodes, tmpl_vars, component_signal_start,
            signal_node_idx, subcomponents, io_map, print_debug, call_stack)
        .must_const_usize(nodes, call_stack);

    let (signal_idx, template_header) = match dest {
        LocationRule::Indexed {
            ref location,
            ref template_header,
        } => {
            let signal_idx =
                calc_expression(
                    location, nodes, tmpl_vars, component_signal_start,
                    signal_node_idx, subcomponents, io_map, print_debug,
                    call_stack)
                .must_const_usize(nodes, call_stack);
            (signal_idx, template_header.as_ref().unwrap_or(&"-".to_string()).clone())
        }
        LocationRule::Mapped { ref signal_code, ref indexes } => {
            calc_mapped_signal_idx(
                subcomponents, subcomponent_idx, io_map,
                signal_code.clone(), indexes, nodes, tmpl_vars,
                component_signal_start, signal_node_idx, print_debug,
                call_stack)
        }
    };

    let signal_offset = subcomponents[subcomponent_idx]
        .as_ref().unwrap().signal_offset;

    if print_debug {
        let location = match dest {
            LocationRule::Indexed { .. } => "Indexed",
            LocationRule::Mapped { .. } => "Mapped",
        };
        println!(
            "Store subcomponent signal (location: {}, template: {}, subcomponent idx: {}, num: {}): {} + {} = {}",
            location, template_header, subcomponent_idx, size, signal_offset,
            signal_idx, signal_offset + signal_idx);
    }

    let signal_idx = signal_offset + signal_idx;
    for i in 0..size {
        if signal_node_idx[signal_idx + i] != usize::MAX {
            panic!("subcomponent signal is already set");
        }
        signal_node_idx[signal_idx + i] = src_node_idxs[i];
    }
    subcomponents[subcomponent_idx].as_mut().unwrap().number_of_inputs -= size;

    let number_of_inputs = subcomponents[subcomponent_idx]
        .as_ref().unwrap().number_of_inputs;

    let run_component = match input_status {
        StatusInput::Last => {
            assert_eq!(number_of_inputs, 0);
            true
        }
        StatusInput::NoLast => {
            assert!(number_of_inputs > 0);
            false
        }
        StatusInput::Unknown => number_of_inputs == 0,
    };

    if run_component {
        run_template(
            templates,
            functions,
            subcomponents[subcomponent_idx]
                .as_ref()
                .unwrap()
                .template_id,
            nodes,
            signal_node_idx,
            subcomponents[subcomponent_idx]
                .as_ref()
                .unwrap()
                .signal_offset,
            io_map,
            print_debug,
            call_stack,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_const_expression() {
        println!("OK");
    }
}

// TODO remove nodes.0 from this file