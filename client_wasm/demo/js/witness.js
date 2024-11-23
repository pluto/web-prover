export function toByte(data) {
  const byteArray = [];
  for (let i = 0; i < data.length; i++) {
    byteArray.push(data.charCodeAt(i));
  }
  return byteArray
}

export function isNullOrSpace(val) {
  return !(val == 0 || val == '\t'.charCodeAt(0) || val == '\n'.charCodeAt(0) || val == '\r'.charCodeAt(0) || val == '\x0C'.charCodeAt(0) || val == ' '.charCodeAt(0));
}

// Function to convert byte array to string
export function byteArrayToString(byteArray) {
  return Array.from(byteArray)
    .map(byte => String.fromCharCode(byte))
    .join('');
}

export function arraysEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  // If you don't care about the order of the elements inside
  // the array, you should sort both arrays here.
  // Please note that calling sort on an array will modify that array.
  // you might want to clone your array first.

  for (var i = 0; i < a.length; ++i) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Function to convert byte array to object with multiple parsing methods
export function byteArrayToObject(byteArray) {
  try {
    // Method 1: Using TextDecoder
    if (typeof TextDecoder !== 'undefined') {
      const decoder = new TextDecoder('utf-8');
      const jsonString = decoder.decode(new Uint8Array(byteArray));
      return JSON.parse(jsonString);
    }

    // Method 2: Manual conversion (fallback)
    const jsonString = byteArrayToString(byteArray);
    return JSON.parse(jsonString);
  } catch (error) {
    throw new Error(`Failed to convert byte array to object: ${error.message}`);
  }
}

export function compute_json_witness(padded_plaintext, key) {
  let plaintext = padded_plaintext.filter(isNullOrSpace);

  let plaintext_as_json = byteArrayToObject(plaintext);
  console.log()
  let data = JSON.stringify(plaintext_as_json[key]);
  let data_bytes = toByte(data);
  data_bytes = data_bytes.filter(isNullOrSpace);

  let startIdx = 0;
  let endIdx = 0;
  for (var i = 0; i < padded_plaintext.length; i++) {
    let filtered_body = padded_plaintext.slice(i, padded_plaintext.length).filter(isNullOrSpace);
    filtered_body = filtered_body.slice(0, data_bytes.length);
    if (arraysEqual(filtered_body, data_bytes) && filtered_body[0] === padded_plaintext[i]) {
      startIdx = i;
    }
  }

  for (var i = 0; i < padded_plaintext.length; i++) {
    let filtered_body = padded_plaintext.slice(0, i + 1).filter(isNullOrSpace);
    filtered_body.reverse();
    filtered_body = filtered_body.slice(0, data_bytes.length);
    filtered_body.reverse();
    if (arraysEqual(filtered_body, data_bytes) && filtered_body[data_bytes.length - 1] === padded_plaintext[i]) {
      endIdx = i;
    }
  }

  let result = [];
  for (var i = 0; i < padded_plaintext.length; i++) {
    if (i >= startIdx && i <= endIdx) {
      result.push(padded_plaintext[i]);
    } else {
      result.push(0);
    }
  }

  return result;
}

export function computeHttpWitnessStartline(paddedPlaintext, httpMaskType) {
  let result = Array(paddedPlaintext.length).fill(0);
  for (var i = 0; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      result.splice(0, i + 2, ...paddedPlaintext.slice(0, i + 2));
      break;
    }
  }

  return result;
}

export function computeHttpWitnessHeader(paddedPlaintext, headerName) {
  let result = Array(paddedPlaintext.length).fill(0);
  let currentHeader = 0;
  let currentHeaderName = [];
  let startPos = 0;

  // skip start line
  for (var i = 0; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      startPos = i + 2;
      break;
    }
  }

  let headerStartPos = startPos;
  for (var i = startPos; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] == ':'.charCodeAt(0)) {
      currentHeaderName = paddedPlaintext.slice(headerStartPos, i);
    }

    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      if (arraysEqual(currentHeaderName, headerName)) {
        result.splice(headerStartPos, i + 2 - headerStartPos, ...paddedPlaintext.slice(headerStartPos, i + 2));
        break;
      }

      if (i + 3 < paddedPlaintext.length && paddedPlaintext[i + 2] === '\r'.charCodeAt(0) && paddedPlaintext[i + 3] === '\n'.charCodeAt(0)) {
        currentHeader = -1;
        break;
      }

      currentHeader = currentHeader + 1;
      headerStartPos = i + 2;
    }
  }

  return [currentHeader, result];
}

export function computeHttpWitnessBody(paddedPlaintext) {
  let result = Array(paddedPlaintext.length).fill(0);
  for (var i = 0; i < paddedPlaintext.length - 3; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0) && paddedPlaintext[i + 2] === '\r'.charCodeAt(0) && paddedPlaintext[i + 3] === '\n'.charCodeAt(0)) {
      if (i + 4 < paddedPlaintext.length) {
        result.splice(i + 4, paddedPlaintext.length - i + 4, ...paddedPlaintext.slice(i + 4));
      }
      break;
    }
  }

  return result;
}