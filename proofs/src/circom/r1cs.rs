use std::{
  collections::HashMap,
  io::{BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom},
};

use arecibo::traits::Group;
use byteorder::{LittleEndian, ReadBytesExt};
use ff::PrimeField;
use fs::OpenOptions;
use io::Cursor;

use super::*;
// This was borrowed from `nova-scotia`. Big thank you for this middleware!
// some codes borrowed from https://github.com/poma/zkutil/blob/master/src/r1cs_reader.rs
use crate::circom::circuit::Constraint;

#[derive(Clone)]
pub struct R1CS {
  pub num_inputs:    usize,
  pub num_aux:       usize,
  pub num_variables: usize,
  pub constraints:   Vec<Constraint<F<G1>>>,
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
    let header = read_header(&mut cursor, *section_sizes.get(&header_type).unwrap()).unwrap();
    assert_eq!(header.field_size, 32);

    cursor.seek(SeekFrom::Start(*section_offsets.get(&constraint_type).unwrap())).unwrap();
    let constraints = read_constraints::<&mut Cursor<&[u8]>, F<G1>>(&mut cursor, &header).unwrap();

    cursor.seek(SeekFrom::Start(*section_offsets.get(&wire2label_type).unwrap())).unwrap();
    let wire_mapping =
      read_map(&mut cursor, *section_sizes.get(&wire2label_type).unwrap(), &header).unwrap();

    let num_inputs = (1 + header.n_pub_in + header.n_pub_out) as usize;
    let num_variables = header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    R1CS { num_aux, num_inputs, num_variables, constraints }
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
pub struct R1CSFile<Fr: PrimeField> {
  pub version:      u32,
  pub header:       Header,
  pub constraints:  Vec<Constraint<Fr>>,
  pub wire_mapping: Vec<u64>,
}

pub(crate) fn read_field<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Fr> {
  let mut repr = Fr::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    *digit = reader.read_u8()?;
  }
  let fr = Fr::from_repr(repr).unwrap();
  Ok(fr)
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header> {
  let field_size = reader.read_u32::<LittleEndian>()?;
  let mut prime_size = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime_size)?;
  if size != 32 + field_size as u64 {
    return Err(Error::new(ErrorKind::InvalidData, "Invalid header section size"));
  }

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

fn read_constraint_vec<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Vec<(usize, Fr)>> {
  let n_vec = reader.read_u32::<LittleEndian>()? as usize;
  let mut vec = Vec::with_capacity(n_vec);
  for _ in 0..n_vec {
    vec.push((reader.read_u32::<LittleEndian>()? as usize, read_field::<&mut R, Fr>(&mut reader)?));
  }
  Ok(vec)
}

fn read_constraints<R: Read, Fr: PrimeField>(
  mut reader: R,
  header: &Header,
) -> Result<Vec<Constraint<Fr>>> {
  // todo check section size
  let mut vec = Vec::with_capacity(header.n_constraints as usize);
  for _ in 0..header.n_constraints {
    vec.push((
      read_constraint_vec::<&mut R, Fr>(&mut reader)?,
      read_constraint_vec::<&mut R, Fr>(&mut reader)?,
      read_constraint_vec::<&mut R, Fr>(&mut reader)?,
    ));
  }
  Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Result<Vec<u64>> {
  if size != header.n_wires as u64 * 8 {
    return Err(Error::new(ErrorKind::InvalidData, "Invalid map section size"));
  }
  let mut vec = Vec::with_capacity(header.n_wires as usize);
  for _ in 0..header.n_wires {
    vec.push(reader.read_u64::<LittleEndian>()?);
  }
  if vec[0] != 0 {
    return Err(Error::new(ErrorKind::InvalidData, "Wire 0 should always be mapped to 0"));
  }
  Ok(vec)
}

pub fn from_reader<R: Read + Seek, G1, G2>(
  mut reader: R,
) -> Result<R1CSFile<<G1 as Group>::Scalar>>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>, {
  let mut magic = [0u8; 4];
  reader.read_exact(&mut magic)?;
  if magic != [0x72, 0x31, 0x63, 0x73] {
    // magic = "r1cs"
    return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
  }

  let version = reader.read_u32::<LittleEndian>()?;
  if version != 1 {
    return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
  }

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

  reader.seek(SeekFrom::Start(*section_offsets.get(&header_type).unwrap()))?;
  let header = read_header(&mut reader, *section_sizes.get(&header_type).unwrap())?;
  if header.field_size != 32 {
    return Err(Error::new(ErrorKind::InvalidData, "This parser only supports 32-byte fields"));
  }

  reader.seek(SeekFrom::Start(*section_offsets.get(&constraint_type).unwrap()))?;
  let constraints = read_constraints::<&mut R, F<G1>>(&mut reader, &header)?;

  reader.seek(SeekFrom::Start(*section_offsets.get(&wire2label_type).unwrap()))?;
  let wire_mapping = read_map(&mut reader, *section_sizes.get(&wire2label_type).unwrap(), &header)?;

  Ok(R1CSFile { version, header, constraints, wire_mapping })
}

/// load r1cs from bin by a reader
pub(crate) fn load_r1cs(filename: &PathBuf) -> R1CS
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>, {
  let reader =
    BufReader::new(OpenOptions::new().read(true).open(filename).expect("unable to open."));

  let file = from_reader::<_, G1, G2>(reader).expect("unable to read.");
  let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
  let num_variables = file.header.n_wires as usize;
  let num_aux = num_variables - num_inputs;
  R1CS { num_aux, num_inputs, num_variables, constraints: file.constraints }
}
