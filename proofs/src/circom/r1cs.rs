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

// NOTE (Colin): This is added so we can cache only the active circuits we are using.
#[allow(clippy::derivable_impls)]
impl Default for R1CS {
  fn default() -> Self {
    Self {
      num_private_inputs: 0,
      num_public_inputs:  0,
      num_public_outputs: 0,
      num_inputs:         0,
      num_aux:            0,
      num_variables:      0,
      constraints:        vec![],
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

impl TryFrom<&R1CSType> for R1CS {
  type Error = ProofError;

  fn try_from(value: &R1CSType) -> Result<Self, Self::Error> {
    match value {
      R1CSType::File { path } => R1CS::try_from(path),
      R1CSType::Raw(bytes) => R1CS::try_from(&bytes[..]),
    }
  }
}

impl TryFrom<&[u8]> for R1CS {
  type Error = ProofError;

  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let cursor = BufReader::new(Cursor::new(value));
    from_reader(cursor)
  }
}

impl TryFrom<&PathBuf> for R1CS {
  type Error = ProofError;

  fn try_from(filename: &PathBuf) -> Result<Self, Self::Error> {
    let reader = BufReader::new(OpenOptions::new().read(true).open(filename)?);
    from_reader(reader)
  }
}

fn from_reader<R: Read + Seek>(mut reader: R) -> Result<R1CS, ProofError> {
  let mut magic = [0u8; 4];
  reader.read_exact(&mut magic)?;
  assert_eq!(magic, [0x72, 0x31, 0x63, 0x73]);

  let version = reader.read_u32::<LittleEndian>()?;
  assert_eq!(version, 1);

  let num_sections = reader.read_u32::<LittleEndian>()?;

  // section type -> file offset
  let mut section_offsets = HashMap::<u32, u64>::new();
  let mut section_sizes = HashMap::<u32, u64>::new();

  // get file offset of each section
  for _ in 0..num_sections {
    let section_type = reader.read_u32::<LittleEndian>()?;
    let section_size = reader.read_u64::<LittleEndian>()?;
    let offset = reader.stream_position()?;
    section_offsets.insert(section_type, offset);
    section_sizes.insert(section_type, section_size);
    reader.seek(SeekFrom::Current(section_size as i64))?;
  }

  let header_type = 1;
  let constraint_type = 2;
  let wire2label_type = 3;

  reader
    .seek(SeekFrom::Start(*section_offsets.get(&header_type).ok_or(ProofError::MissingSection)?))?;
  let header_size = section_sizes.get(&header_type).ok_or(ProofError::MissingSection)?;
  let header = read_header(&mut reader, *header_size)?;
  assert_eq!(header.field_size, 32);

  reader.seek(SeekFrom::Start(
    *section_offsets.get(&constraint_type).ok_or(ProofError::MissingSection)?,
  ))?;
  let constraints = read_constraints(&mut reader, &header)?;

  reader.seek(SeekFrom::Start(
    *section_offsets.get(&wire2label_type).ok_or(ProofError::MissingSection)?,
  ))?;

  let num_public_inputs = header.n_pub_in as usize;
  let num_private_inputs = header.n_prv_in as usize;
  let num_public_outputs = header.n_pub_out as usize;
  let num_variables = header.n_wires as usize;
  let num_inputs = (1 + header.n_pub_in + header.n_pub_out) as usize; // TODO: This seems... odd...
  let num_aux = num_variables - num_inputs;
  Ok(R1CS {
    num_private_inputs,
    num_public_inputs,
    num_public_outputs,
    num_inputs,
    num_aux,
    num_variables,
    constraints,
  })
}

fn read_field<R: Read>(mut reader: R) -> Result<F<G1>, ProofError> {
  let mut repr = F::<G1>::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    *digit = reader.read_u8()?;
  }
  // TODO(WJ 2024-11-05): there might be a better way to do this, but the constant time option type
  // is weird `CTOption`
  let fr = F::<G1>::from_repr(repr);
  if fr.is_some().into() {
    Ok(fr.unwrap())
  } else {
    Err(ProofError::Other("Failed to convert representation to field element".to_string()))
  }
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header, ProofError> {
  let field_size = reader.read_u32::<LittleEndian>()?;
  let mut prime_size = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime_size)?;
  assert_eq!(size, 32 + field_size as u64);

  Ok(Header {
    field_size,
    prime_size,
    n_wires: reader.read_u32::<LittleEndian>()?,
    n_pub_out: reader.read_u32::<LittleEndian>()?,
    n_pub_in: reader.read_u32::<LittleEndian>()?,
    n_prv_in: reader.read_u32::<LittleEndian>()?,
    n_labels: reader.read_u64::<LittleEndian>()?,
    n_constraints: reader.read_u32::<LittleEndian>()?,
  })
}

fn read_constraint_vec<R: Read>(mut reader: R) -> Result<Vec<(usize, F<G1>)>, ProofError> {
  let n_vec = reader.read_u32::<LittleEndian>()? as usize;
  let mut vec = Vec::with_capacity(n_vec);
  for _ in 0..n_vec {
    vec.push((reader.read_u32::<LittleEndian>()? as usize, read_field::<&mut R>(&mut reader)?));
  }
  Ok(vec)
}

fn read_constraints<R: Read>(
  mut reader: R,
  header: &Header,
) -> Result<Vec<Constraint>, ProofError> {
  // todo check section size
  let mut vec = Vec::with_capacity(header.n_constraints as usize);
  for _ in 0..header.n_constraints {
    let a = read_constraint_vec(&mut reader)?;
    let b = read_constraint_vec(&mut reader)?;
    let c = read_constraint_vec(&mut reader)?;
    vec.push((a, b, c));
  }
  Ok(vec)
}

#[cfg(test)]
mod tests {
  use super::*;

  const ADD_EXTERNAL_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/add_external.r1cs");

  #[test]
  #[tracing_test::traced_test]
  fn test_r1cs_from_bin() {
    let r1cs = R1CS::try_from(ADD_EXTERNAL_R1CS).unwrap();
    assert_eq!(r1cs.num_inputs, 5); // TODO: What is the 5th input??
    assert_eq!(r1cs.num_private_inputs, 2);
    assert_eq!(r1cs.num_public_inputs, 2);
    assert_eq!(r1cs.num_public_outputs, 2);
  }
}
