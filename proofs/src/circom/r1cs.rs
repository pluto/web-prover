use ff::PrimeField;
use fs::OpenOptions;

use super::*;
// This was borrowed from `nova-scotia`. Big thank you for this middleware!
// some codes borrowed from https://github.com/poma/zkutil/blob/master/src/r1cs_reader.rs

pub type Constraint = (Vec<(usize, F<G1>)>, Vec<(usize, F<G1>)>, Vec<(usize, F<G1>)>);

#[derive(Clone, Debug)]
pub struct R1CS {
  pub num_private_inputs: usize,
  pub num_public_inputs:  usize,
  pub num_public_outputs: usize,
  pub num_inputs:         usize,
  pub num_aux:            usize,
  pub num_variables:      usize,
  pub constraints:        Vec<Constraint>,
}

impl From<&[u8]> for R1CS {
  fn from(value: &[u8]) -> Self {
    let mut cursor = Cursor::new(value);

    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic).unwrap();
    assert_eq!(magic, [0x72, 0x31, 0x63, 0x73]);

    let version = cursor.read_u32::<LittleEndian>().unwrap();
    assert_eq!(version, 1);

    let num_sections = cursor.read_u32::<LittleEndian>().unwrap();

    let mut section_offsets = HashMap::<u32, u64>::new();
    let mut section_sizes = HashMap::<u32, u64>::new();

    for _ in 0..num_sections {
      let section_type = cursor.read_u32::<LittleEndian>().unwrap();
      let section_size = cursor.read_u64::<LittleEndian>().unwrap();
      let offset = cursor.position();
      section_offsets.insert(section_type, offset);
      section_sizes.insert(section_type, section_size);
      cursor.seek(SeekFrom::Current(section_size as i64)).unwrap();
    }

    let header_type = 1;
    let constraint_type = 2;
    let wire2label_type = 3;

    cursor.seek(SeekFrom::Start(*section_offsets.get(&header_type).unwrap())).unwrap();
    let header = read_header(&mut cursor, *section_sizes.get(&header_type).unwrap());
    assert_eq!(header.field_size, 32);

    cursor.seek(SeekFrom::Start(*section_offsets.get(&constraint_type).unwrap())).unwrap();
    let constraints = read_constraints(&mut cursor, &header);

    cursor.seek(SeekFrom::Start(*section_offsets.get(&wire2label_type).unwrap())).unwrap();
    // TODO: not using wiremapping is cursed fs
    let _wire_mapping =
      read_map(&mut cursor, *section_sizes.get(&wire2label_type).unwrap(), &header);

    let num_public_inputs = header.n_pub_in as usize;
    let num_private_inputs = header.n_prv_in as usize;
    let num_public_outputs = header.n_pub_out as usize;
    let num_variables = header.n_wires as usize;
    let num_inputs = (1 + header.n_pub_in + header.n_pub_out) as usize;
    let num_aux = num_variables - num_inputs;
    R1CS {
      num_private_inputs,
      num_public_inputs,
      num_public_outputs,
      num_inputs,
      num_aux,
      num_variables,
      constraints,
    }
  }
}

// R1CSFile's header
#[derive(Debug, Default)]
pub struct Header {
  pub field_size:    u32,
  pub prime_size:    Vec<u8>,
  pub n_wires:       u32,
  pub n_pub_out:     u32,
  pub n_pub_in:      u32,
  pub n_prv_in:      u32,
  pub n_labels:      u64,
  pub n_constraints: u32,
}

// R1CSFile parse result
#[derive(Debug, Default)]
pub struct R1CSFile {
  pub version:      u32,
  pub header:       Header,
  pub constraints:  Vec<Constraint>,
  pub wire_mapping: Vec<u64>,
}

/// load r1cs from bin by a reader
pub fn load_r1cs_from_file(filename: &PathBuf) -> R1CS {
  let reader =
    BufReader::new(OpenOptions::new().read(true).open(filename).expect("unable to open."));

  let file = from_reader(reader);
  let num_public_inputs = file.header.n_pub_in as usize;
  let num_private_inputs = file.header.n_prv_in as usize;
  let num_public_outputs = file.header.n_pub_out as usize;
  let num_variables = file.header.n_wires as usize;
  let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
  let num_aux = num_variables - num_inputs;
  R1CS {
    num_private_inputs,
    num_public_inputs,
    num_public_outputs,
    num_variables,
    num_inputs,
    num_aux,
    constraints: file.constraints,
  }
}

pub(crate) fn read_field<R: Read>(mut reader: R) -> F<G1> {
  let mut repr = F::<G1>::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    *digit = reader.read_u8().unwrap();
  }
  F::<G1>::from_repr(repr).unwrap()
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Header {
  let field_size = reader.read_u32::<LittleEndian>().unwrap();
  let mut prime_size = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime_size).unwrap();
  assert_eq!(size, 32 + field_size as u64);

  Header {
    field_size,
    prime_size,
    n_wires: reader.read_u32::<LittleEndian>().unwrap(),
    n_pub_out: reader.read_u32::<LittleEndian>().unwrap(),
    n_pub_in: reader.read_u32::<LittleEndian>().unwrap(),
    n_prv_in: reader.read_u32::<LittleEndian>().unwrap(),
    n_labels: reader.read_u64::<LittleEndian>().unwrap(),
    n_constraints: reader.read_u32::<LittleEndian>().unwrap(),
  }
}

fn read_constraint_vec<R: Read>(mut reader: R) -> Vec<(usize, F<G1>)> {
  let n_vec = reader.read_u32::<LittleEndian>().unwrap() as usize;
  let mut vec = Vec::with_capacity(n_vec);
  for _ in 0..n_vec {
    vec.push((
      reader.read_u32::<LittleEndian>().unwrap() as usize,
      read_field::<&mut R>(&mut reader),
    ));
  }
  vec
}

fn read_constraints<R: Read>(mut reader: R, header: &Header) -> Vec<Constraint> {
  // todo check section size
  let mut vec = Vec::with_capacity(header.n_constraints as usize);
  for _ in 0..header.n_constraints {
    vec.push((
      read_constraint_vec(&mut reader),
      read_constraint_vec(&mut reader),
      read_constraint_vec(&mut reader),
    ));
  }
  vec
}

fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Vec<u64> {
  assert_eq!(size, header.n_wires as u64 * 8);
  let mut vec = Vec::with_capacity(header.n_wires as usize);
  for _ in 0..header.n_wires {
    vec.push(reader.read_u64::<LittleEndian>().unwrap());
  }
  assert_eq!(vec[0], 0);
  vec
}

pub fn from_reader<R: Read + Seek>(mut reader: R) -> R1CSFile
where {
  let mut magic = [0u8; 4];
  reader.read_exact(&mut magic).unwrap();
  assert_eq!(magic, [0x72, 0x31, 0x63, 0x73]);

  let version = reader.read_u32::<LittleEndian>().unwrap();
  assert_eq!(version, 1);

  let num_sections = reader.read_u32::<LittleEndian>().unwrap();

  // section type -> file offset
  let mut section_offsets = HashMap::<u32, u64>::new();
  let mut section_sizes = HashMap::<u32, u64>::new();

  // get file offset of each section
  for _ in 0..num_sections {
    let section_type = reader.read_u32::<LittleEndian>().unwrap();
    let section_size = reader.read_u64::<LittleEndian>().unwrap();
    let offset = reader.stream_position().unwrap();
    section_offsets.insert(section_type, offset);
    section_sizes.insert(section_type, section_size);
    reader.seek(SeekFrom::Current(section_size as i64)).unwrap();
  }

  let header_type = 1;
  let constraint_type = 2;
  let wire2label_type = 3;

  reader.seek(SeekFrom::Start(*section_offsets.get(&header_type).unwrap())).unwrap();
  let header = read_header(&mut reader, *section_sizes.get(&header_type).unwrap());
  assert_eq!(header.field_size, 32);

  reader.seek(SeekFrom::Start(*section_offsets.get(&constraint_type).unwrap())).unwrap();
  let constraints = read_constraints(&mut reader, &header);

  reader.seek(SeekFrom::Start(*section_offsets.get(&wire2label_type).unwrap())).unwrap();
  let wire_mapping = read_map(&mut reader, *section_sizes.get(&wire2label_type).unwrap(), &header);

  R1CSFile { version, header, constraints, wire_mapping }
}

#[cfg(test)]
mod tests {
  use super::*;

  const PARSE_FOLD_R1CS: &[u8] =
    include_bytes!("../../examples/circuit_data/parse_fold_batch.r1cs");

  #[test]
  #[tracing_test::traced_test]
  fn test_r1cs_from_bin() {
    let r1cs = R1CS::from(PARSE_FOLD_R1CS);
    assert_eq!(r1cs.num_public_inputs, 6);
    assert_eq!(r1cs.num_private_inputs, 40);
  }
}
