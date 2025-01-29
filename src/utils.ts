/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

/**
 * Converts a Base64-encoded string to an Uint8Array.
 *
 * @param base64 - The Base64-encoded string to convert.
 * @returns The resulting Uint8Array.
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  // Decode the Base64-encoded string into a binary string
  const binaryString: string = atob(base64);

  // Create a Uint8Array to hold the decoded bytes
  const byteArray: Uint8Array = new Uint8Array(binaryString.length);

  // Convert each character in the binary string to a byte in the Uint8Array
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }

  // Return the Uint8Array
  return byteArray;
}

/**
 * Converts a hex string to an Uint8Array.
 *
 * @param hex - The hex string to convert.
 * @returns The resulting Uint8Array.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  // Ensure the hex string has an even length
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }

  // Create a Uint8Array to hold the bytes
  const bytes = new Uint8Array(hex.length / 2);

  // Convert each pair of hex characters to a byte
  for (let i: number = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  // Return the the Uint8Array
  return bytes;
}

/**
 * Concatenate two ArrayBuffers.
 *
 * @param buffer1 - The first ArrayBuffer to concatenate.
 * @param buffer2 - The second ArrayBuffer to concatenate.
 * @returns A new ArrayBuffer containing the concatenated data of buffer1 and buffer2.
 */
export function mergeBuffer(buffer1: Uint8Array, buffer2: Uint8Array): Uint8Array {
  // If buffer1 is null or undefined, return buffer2
  if (!buffer1) {
    return buffer2;
  }
  // If buffer2 is null or undefined, return buffer1
  else if (!buffer2) {
    return buffer1;
  }

  // Create a new Uint8Array to hold the concatenated data
  const concatenatedBuffer = new Uint8Array(buffer1.byteLength + buffer2.byteLength);

  // Set the data from buffer1 into the new Uint8Array
  concatenatedBuffer.set(buffer1, 0);

  // Set the data from buffer2 into the new Uint8Array, starting at the end of buffer1's data
  concatenatedBuffer.set(buffer2, buffer1.byteLength);

  // Return the ArrayBuffer representation of the concatenated Uint8Array
  return concatenatedBuffer;
}

/**
 * Creates a Date object from a string in the format YYYYMMDDHHMMSS.sssssssss or YYYYMMDDHHMMSS.
 *
 * @param dateString - The input date string in the format YYYYMMDDHHMMSS.sssssssss or YYYYMMDDHHMMSS.
 * @returns A Date object representing the input date and time.
 */
export function createDate(dateString: string): Date {
  //get accuracy if any
  let accuracy;
  let accuracy_chuncks = dateString.split('.');

  if (accuracy_chuncks[1]) {
    dateString = accuracy_chuncks[0];
    accuracy = accuracy_chuncks[1];
  } else {
    accuracy = '000';
  }

  // Regular expression to match the components of the date string
  const datePattern = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;

  // Replace the matched components with the format required by the Date constructor
  const formattedDateString = dateString.replace(datePattern, '$1-$2-$3T$4:$5:$6.' + accuracy + 'Z');

  // Create and return a new Date object using the formatted date string
  return new Date(formattedDateString);
}
