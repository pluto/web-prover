use tracing::{debug, info};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct WitnessOutput {
  pub data: js_sys::Uint8Array,
}

#[wasm_bindgen]
impl WitnessOutput {
  #[wasm_bindgen(constructor)]
  pub fn new(wit: js_sys::Uint8Array) -> WitnessOutput { Self { data: wit } }
}

#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = witness, js_name = createWitness)]
  async fn create_witness_js(input: &JsValue, opcode: u64) -> JsValue;
}

#[wasm_bindgen]
pub async fn create_witness(input: JsValue, opcode: u64) -> Result<WitnessOutput, JsValue> {
  // Convert the Rust WitnessInput to a JsValue
  let js_witnesses_output = create_witness_js(&input, opcode).await;

  // Call JavaScript function and await the Promise
  info!("result: {:?}", js_witnesses_output);
  let js_obj = js_sys::Object::from(js_witnesses_output);
  let data_value = js_sys::Reflect::get(&js_obj, &JsValue::from_str("data"))?;
  let array = js_sys::Array::from(&data_value);
  let data = js_sys::Uint8Array::new(&array);

  debug!("data: {:?}", data);
  Ok(WitnessOutput { data })
}
