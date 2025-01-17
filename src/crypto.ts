/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

import { base64ToUint8Array, mergeBuffer } from './utils';

interface ECDSASigningAlgorithm {
  name: 'ECDSA';
  namedCurve: ECDSANamedCurve;
  hash: HashAlgorithm;
}

interface PKCSV1_5SigningAlgorithm {
  name: 'RSASSA-PKCS1-v1_5';
  hash: { name: HashAlgorithm };
}

type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

type ECDSANamedCurve = 'P-256' | 'P-384' | 'P-521';

type SigningAlgorithm = ECDSASigningAlgorithm | PKCSV1_5SigningAlgorithm;

export class Crypto {
  public static getAlgorithmParameters(publicKey: string, digestAlgorithm: string, keyAlgorithm: string): SigningAlgorithm {
    let algorithmParameters: SigningAlgorithm;

    let hash: HashAlgorithm = digestAlgorithm as HashAlgorithm;

    if (keyAlgorithm == 'rsa') {
      algorithmParameters = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: hash },
      };
    } else if (keyAlgorithm == 'ec') {
      let named_curve: ECDSANamedCurve;
      switch (publicKey.length) {
        case 91:
          named_curve = 'P-256'; // Assuming ECDSA P-256: 91 bytes
          break;
        case 120:
          named_curve = 'P-384'; // Assuming ECDSA P-384: 120 bytes
          break;
        case 156:
          named_curve = 'P-521'; // Assuming ECDSA P-521: 156 bytes
          break;
        default:
          named_curve = 'P-256';
          break;
      }

      algorithmParameters = {
        name: 'ECDSA',
        hash: hash,
        namedCurve: named_curve,
      };
    } else {
      algorithmParameters = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: hash },
      };
    }
    return algorithmParameters;
  }

  public static getCryptoKeyLength(key: CryptoKey) {
    let keyLength;
    if (key.algorithm.name === 'ECDSA') {
      keyLength = parseInt(key.algorithm.namedCurve.replace('P-', ''));
    }
    if (key.algorithm.name === 'RSASSA-PKCS1-v1_5') {
      keyLength = key.algorithm.modulusLength;
    }
    return keyLength;
  }

  /**
   * Imports a public key for use in cryptographic operations.
   *
   * @param {string} publicKey - The base64-encoded public key string.
   * @param {SigningAlgorithm} algorithmParameters - The parameters of the cryptographic algorithm to use.
   * @returns {Promise<CryptoKey>} - A promise that resolves to the imported CryptoKey.
   * @throws {ValidationError} - If the key import process fails.
   */
  public static async importCryptoKey(publicKey: string, algorithmParameters: SigningAlgorithm): Promise<CryptoKey> {
    return new Promise(async (resolve, reject) => {
      const key = await crypto.subtle
        .importKey('spki', base64ToUint8Array(publicKey), algorithmParameters, true, ['verify'])
        .catch((error) => {
          reject(error);
        });
      resolve(key as CryptoKey);
    });
  }

  /**
   * Verifies the digital signature of the given payload using the provided cryptographic key and algorithm parameters.
   *
   * @param {Uint8Array} payload - The data payload to verify the signature against.
   * @param {Uint8Array} signature - The digital signature to verify.
   * @param {CryptoKey} cryptoKey - The cryptographic key used for verification.
   * @param {SigningAlgorithm} algorithmParameters - The parameters of the cryptographic algorithm to use.
   * @returns {Promise<boolean>} - A promise that resolves to true if the signature is valid, false otherwise.
   */
  public static async verifySignature(
    payload: Uint8Array,
    signature: Uint8Array,
    cryptoKey: CryptoKey,
    algorithmParameters: SigningAlgorithm,
  ): Promise<boolean> {
    // Convert ECDSA signature from ASN.1 representation to IEEE P1363 representation
    if (cryptoKey.algorithm.name === 'ECDSA') {
      signature = Crypto.convertEcdsaAsn1Signature(signature);
    }
    // Verify the signature using the SubtleCrypto API and return the result
    return crypto.subtle.verify(algorithmParameters, cryptoKey, signature, payload);
  }

  /**
   * Converts an ECDSA ASN.1 signature into a raw format.
   * ref: https://www.criipto.com/blog/webauthn-ecdsa-signature
   *
   * @param {Uint8Array} input - The input buffer containing the ASN.1 signature.
   * @returns {Uint8Array} - The converted raw ECDSA signature.
   * @throws {Error} - If the input does not contain exactly 2 ASN.1 sequence elements,
   *                   or if there are length inconsistencies in the R and S values.
   */
  private static convertEcdsaAsn1Signature(input: Uint8Array): Uint8Array {
    // Read the ASN.1 integer sequence elements from the input.
    const elements = Crypto.readAsn1IntegerSequence(input);
    if (elements.length !== 2) throw new Error('Expected 2 ASN.1 sequence elements');
    let [r, s] = elements;

    // R and S length is assumed to be a multiple of 128 bits (16 bytes).
    // If the leading byte is 0 and the length modulo 16 is 1,
    // the leading 0 is for two's complement and will be removed.
    if (r[0] === 0 && r.byteLength % 16 == 1) {
      r = r.slice(1);
    }
    if (s[0] === 0 && s.byteLength % 16 == 1) {
      s = s.slice(1);
    }

    // If R and S length is missing a byte (length % 16 == 15),
    // pad the value with a leading 0.
    if (r.byteLength % 16 == 15) {
      r = new Uint8Array(mergeBuffer(new Uint8Array([0]), r));
    }
    if (s.byteLength % 16 == 15) {
      s = new Uint8Array(mergeBuffer(new Uint8Array([0]), s));
    }

    // If R and S length is still not a multiple of 128 bits, throw an error.
    if (r.byteLength % 16 != 0) throw new Error('unknown ECDSA sig r length error');
    if (s.byteLength % 16 != 0) throw new Error('unknown ECDSA sig s length error');

    // Merge the R and S values into a single buffer and return it.
    return mergeBuffer(r, s);
  }

  /**
   * Reads an ASN.1 integer sequence from the input Uint8Array.
   *
   * @param {Uint8Array} input - The input buffer containing the ASN.1 sequence.
   * @returns {Uint8Array[]} - An array of Uint8Array elements representing the integers in the sequence.
   * @throws {Error} - If the input is not a valid ASN.1 sequence or if an element is not an INTEGER.
   */
  private static readAsn1IntegerSequence(input: Uint8Array): Uint8Array[] {
    // Check if the input starts with the ASN.1 SEQUENCE tag (0x30).
    if (input[0] !== 0x30) throw new Error('Input is not an ASN.1 sequence');

    // Get the length of the sequence.
    const seqLength = input[1];
    const elements: Uint8Array[] = [];

    // Slice the input to get the sequence content.
    let current = input.slice(2, 2 + seqLength);

    // Loop through the sequence content to extract INTEGER elements.
    while (current.length > 0) {
      const tag = current[0];

      // Check if the tag is the ASN.1 INTEGER tag (0x02).
      if (tag !== 0x02) throw new Error('Expected ASN.1 sequence element to be an INTEGER');

      // Get the length of the INTEGER element.
      const elLength = current[1];

      // Push the INTEGER element into the elements array.
      elements.push(current.slice(2, 2 + elLength));

      // Slice the current buffer to process the next element.
      current = current.slice(2 + elLength);
    }

    // Return the array of INTEGER elements.
    return elements;
  }
}
