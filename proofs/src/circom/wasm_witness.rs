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
unsafe extern "C" {
  // Foreign function binding to JavaScript's createWitness
  #[wasm_bindgen(js_namespace = witness, js_name = createWitness)]
  fn create_witness_js(input: &JsValue, opcode: u64) -> js_sys::Promise;
}

#[wasm_bindgen]
pub async fn create_witness(input: JsValue, opcode: u64) -> Result<WitnessOutput, JsValue> {
  // Call the JavaScript function, which returns a Promise
  let promise: js_sys::Promise = unsafe { create_witness_js(&input, opcode) };

  // Await the resolution of the promise
  let js_witnesses_output = wasm_bindgen_futures::JsFuture::from(promise).await?;

  // Convert the result to a WitnessOutput
  let js_obj = js_sys::Object::from(js_witnesses_output);
  let data_value = js_sys::Reflect::get(&js_obj, &JsValue::from_str("data"))?;
  let array = js_sys::Array::from(&data_value);
  let data = js_sys::Uint8Array::new(&array);

  debug!("data: {:?}", data);
  Ok(WitnessOutput { data })
}
