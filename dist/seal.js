import {
  mediaAsset
} from "./chunk-Z6HUMCJD.js";
import "./chunk-APGEQWFO.js";

// src/seal.ts
var textEncoder = new TextEncoder();
var ValidationError = class extends Error {
  name;
  // Specific type for error name
  cause;
  // Optional cause of the error
  /**
   * Constructor to initialize ValidationError instance
   * @param name - The name of the error
   * @param message - The error message
   * @param cause - (Optional) The underlying cause of the error
   */
  constructor({ name, message, cause }) {
    super(message);
    this.name = name;
    this.cause = cause;
  }
};
var SEAL = class _SEAL {
  static public_keys = {};
  static seals = [];
  static record;
  static validation;
  /**
   * Parses the SEAL segment string in the asset and extracts parameters.
   *
   * @param asset - The asset object containing SEAL segments.
   */
  static parse(asset) {
    console.time("parse");
    const sealSegmentString = asset.seal_segments[0].string.replace(/<.{0,1}seal /, "").replace(/\?{0,1}\/>/, "").replace(/&quot;/g, '"').replace("<seal:seal>", "").replace("/&", "").replace("&lt;seal ", "");
    const sealRecord = {};
    const parameterPattern = / ?(.*?)=\"(.*?)\"/gm;
    let match;
    while ((match = parameterPattern.exec(sealSegmentString)) !== null) {
      if (match.index === parameterPattern.lastIndex) {
        parameterPattern.lastIndex++;
      }
      sealRecord[match[1]] = match[2];
    }
    if (!sealRecord.da) {
      sealRecord.da = "sha256";
    }
    switch (sealRecord.da) {
      case "sha256":
        sealRecord.da = "SHA-256";
        break;
      case "sha384":
        sealRecord.da = "SHA-384";
        break;
      case "sha512":
        sealRecord.da = "SHA-512";
        break;
      case "sha1":
        sealRecord.da = "SHA-1";
        break;
      default:
        sealRecord.da = "SHA-256";
        break;
    }
    if (sealRecord.seal && sealRecord.d && sealRecord.ka && sealRecord.s) {
      this.record = sealRecord;
    } else {
      throw new ValidationError({
        name: "SEAL_RECORD_MISSING_PARAMETERS",
        message: "The SEAL record is incomplete"
      });
    }
    console.timeEnd("parse");
  }
  static async validateSig(asset) {
    return new Promise(async (resolve, reject) => {
      this.validation = { digest_summary: "", signature_bytes: new Uint8Array(), signature_encoding: "" };
      let result_string;
      if (!this.public_keys[this.record.d]) {
        await this.getDNS(this.record.d, "mozilla").catch((error) => {
          return reject(
            new ValidationError({
              name: "DNS_LOOKUP",
              message: "Querying DoH DNS for public key failed",
              cause: error
            })
          );
        });
      }
      await _SEAL.digest(asset);
      await _SEAL.doubleDigest();
      let algorithmParameters = this.getAlgorithmParameters(
        this.public_keys[this.record.d][this.record.ka].p,
        this.record.da,
        this.record.ka
      );
      let cryptoKey = await _SEAL.importCryptoKey(this.public_keys[this.record.d][this.record.ka].p, algorithmParameters);
      if (this.validation.digest2 && this.validation.signature && cryptoKey) {
        console.time("verifySignature");
        let result = await this.verifySignature(
          this.validation.digest2,
          this.validation.signature_bytes,
          cryptoKey,
          algorithmParameters
        ).catch((error) => {
          reject(
            new ValidationError({
              name: "VALIDATION_GENERAL_ERROR",
              message: "crypto.subtle.verify couldn't process the data",
              cause: error
            })
          );
        });
        console.timeEnd("verifySignature");
        if (result !== false) {
          result_string = `${asset.mimeType}:[${asset.filename}]
\u2705 SEAL record #1 is valid.`;
        } else {
          result_string = `${asset.mimeType}:[${asset.filename}]
\u26D4 SEAL record #1 is NOT valid.`;
        }
        if (this.validation.signature_date) {
          result_string = result_string + "\nDate: " + createDate(this.validation.signature_date);
        }
        this.validation.digest2 = new Uint8Array(await crypto.subtle.digest(this.record.da, this.validation.digest2));
        let key_length = this.getCryptoKeyLength(cryptoKey);
        let summary = `${result_string}
Signature Algorithm: ${this.record.ka.toUpperCase()}, ${key_length} bits
Digest Algorithm: ${this.record.da}
Digest: ${Array.from(this.validation.digest1).map((bytes) => bytes.toString(16).padStart(2, "0")).join("")}
Double Digest: ${Array.from(this.validation.digest2).map((bytes) => bytes.toString(16).padStart(2, "0")).join("")}
Signed Bytes: ${this.validation.digest_ranges}
Signature Spans: ${this.validation.digest_summary}
Signed By: ${this.record.d} for user ${this.record.id}
Copyright: ${this.record.copyright}
Comment: ${this.record.info}`;
        resolve({ result, summary });
      } else {
        reject(
          new ValidationError({
            name: "VALIDATION_MISSING_PARAMETERS",
            message: "Double Digest or Signature is missing"
          })
        );
      }
    });
  }
  /**
   * getDNS(): Given a hostname and a DoH provider, get SEAL keys from DNS.
   * Returns: Public key in 'public_keys', revoke in 'revoke'.
   * Errors are detailed in 'error'
   *
   * @static
   * @param {string} hostname
   * @param {string} [doh='cloudflare']
   * @return {*}  {Promise<string[]>}
   * @memberof SEAL
   */
  static async getDNS(hostname, doh = "cloudflare") {
    console.time("getDNS_" + doh);
    return new Promise(async (resolve, reject) => {
      let fetchUrl;
      this.public_keys[hostname] = {};
      const providers = {
        cloudflare: "https://cloudflare-dns.com/dns-query",
        mozilla: "https://mozilla.cloudflare-dns.com/dns-query",
        google: "https://dns.googe/resolve"
      };
      fetchUrl = `${providers[doh]}?name=${hostname}&type=TXT`;
      let publicKeys = [];
      let response = await fetch(fetchUrl, {
        method: "GET",
        headers: {
          accept: "application/dns-json"
        }
      }).catch((error) => {
        reject(error);
      });
      if (response) {
        try {
          let data = await response.json();
          data.Answer.forEach((record) => {
            let keyObject = {};
            if (record.data.includes("seal")) {
              const keyElements = record.data.replace(/"/g, "").split(" ");
              keyElements.forEach((element) => {
                const keyValuePair = element.split("=");
                keyObject[keyValuePair[0]] = keyValuePair[1];
              });
              publicKeys.push(keyObject);
            }
          });
          publicKeys.forEach((key) => {
            if (key.ka === "rsa") {
              this.public_keys[hostname].rsa = key;
            }
            if (key.ka === "ec") {
              this.public_keys[hostname].ec = key;
            }
          });
          console.timeEnd("getDNS_" + doh);
        } catch (error) {
          console.timeEnd("getDNS_" + doh);
          reject(error);
        }
        resolve(this.public_keys[hostname]);
      }
    });
  }
  /**
   * digest(): Given a file, compute the digest!
   * Computes the digest and stores binary data in @digest1.
   * Stores the byte range in 'digest_range'.
   * Sets 'digest_summary' to store summaries of range
   * Any error messages are stored in error.
   * @private
   * @static
   * @memberof SEAL
   */
  static async digest(asset) {
    return new Promise(async (resolve, reject) => {
      console.time("digest");
      this.validation.digest_ranges = [];
      let show_range_start;
      let show_range_stop;
      if (this.record.b) {
        let digest_ranges = this.record.b.split(",");
        digest_ranges.forEach((digest_range) => {
          let start;
          let stop;
          [start, stop] = digest_range.split("~");
          let sub = start.split("-");
          let add = start.split("+");
          if (sub[1]) {
            start = sub[0];
            sub = parseInt(sub[1]);
          } else {
            sub = 0;
          }
          if (add[1]) {
            start = add[0];
            add = parseInt(add[1]);
          } else {
            add = 0;
          }
          switch (start) {
            case "F":
              start = 0;
              if (!show_range_start) {
                show_range_start = "Start of file";
              }
              break;
            case "f":
              start = asset.getDataLength();
              if (!show_range_start) {
                show_range_start = "End of file";
              }
              break;
            case "S":
              start = asset.seal_segments[0].signature_end - this.record.s.length;
              if (!show_range_start) {
                show_range_start = "Start of signature";
              }
              break;
            case "s":
              start = asset.seal_segments[0].signature_end;
              if (!show_range_start) {
                show_range_start = "End of signature";
              }
              break;
            case "P":
              start = 0;
              break;
            case "p":
              start = 0;
              break;
            default:
              reject(
                new ValidationError({
                  name: "SEAL_RANGES",
                  message: "ranges start error"
                })
              );
              break;
          }
          start = start + add + sub;
          sub = stop.split("-");
          add = stop.split("+");
          if (sub[1]) {
            stop = sub[0];
            sub = parseInt(sub[1]);
          } else {
            sub = 0;
          }
          if (add[1]) {
            stop = add[0];
            add = parseInt(add[1]);
          } else {
            add = 0;
          }
          switch (stop) {
            case "F":
              stop = 0;
              show_range_stop = "Start of file";
              break;
            case "f":
              stop = asset.getDataLength();
              show_range_stop = "End of file";
              break;
            case "S":
              stop = asset.seal_segments[0].signature_end - this.record.s.length;
              show_range_stop = "start of signature";
              break;
            case "s":
              stop = asset.seal_segments[0].signature_end;
              show_range_stop = "end of signature";
              break;
            case "P":
              stop = 0;
              break;
            case "p":
              stop = 0;
              break;
            default:
              reject(
                new ValidationError({
                  name: "SEAL_RANGES",
                  message: "ranges stop error"
                })
              );
              break;
          }
          stop = stop + add + sub;
          this.validation.digest_ranges?.push([start, stop]);
          this.validation.digest_summary = `${show_range_start} to ${show_range_stop}`;
        });
        crypto.subtle.digest(this.record.da, asset.assembleBuffer(this.validation.digest_ranges)).then((digest) => {
          this.validation.digest1 = new Uint8Array(digest);
          console.timeEnd("digest");
          resolve();
        });
      }
    });
  }
  /**
   * If there's a date or id (user_id), then add them to the digest.
   * This uses binary 'digest1', 'id', 'signature_date', and 'da'.
   * Computes the digest and places new data in digest2.
   * Any error messages are stored in error.
   *
   * @private
   * @static
   * @memberof SEAL
   */
  static doubleDigest() {
    return new Promise(async (resolve, reject) => {
      console.time("doubleDigest");
      let signature_formats = [];
      if (this.record.sf) {
        signature_formats = this.record.sf.split(":");
      }
      if (this.record.s) {
        this.validation.signature = this.record.s;
        try {
          if (signature_formats.length > 0) {
            signature_formats.forEach((format) => {
              if (format == "base64" || format == "hex" || format == "HEX" || format == "bin") {
                this.validation.signature_encoding = format;
                if (this.validation.signature) this.validation.signature = this.validation.signature.replace(format + ":", "");
              }
              if (format.includes("date")) {
                let accuracy = parseInt(format.charAt(format.length - 1));
                if (isNaN(accuracy)) {
                  this.validation.signature = this.record.s.substring(15, this.record.s.length);
                  accuracy = 0;
                } else {
                  this.validation.signature = this.record.s.substring(16 + accuracy, this.record.s.length);
                }
                this.validation.signature_date = this.record.s.substring(0, 15 + accuracy);
              }
            });
          } else {
            this.validation.signature_encoding = "base64";
          }
          if (this.validation.signature_encoding == "hex" || this.validation.signature_encoding == "HEX") {
            this.validation.signature_bytes = hexToUint8Array(this.validation.signature);
          }
          if (this.validation.signature_encoding == "base64") {
            this.validation.signature_bytes = base64ToUint8Array(this.validation.signature);
          }
        } catch (error) {
          reject(
            new ValidationError({
              name: "SIGNATURE_FORMAT",
              message: "The signature format is not valid or corrupted"
            })
          );
        }
      } else {
        reject(
          new ValidationError({
            name: "SIGNATURE_MISSING",
            message: "The signature is missing"
          })
        );
      }
      let prepend = "";
      if (this.validation.signature_date) {
        prepend = this.validation.signature_date + ":";
      }
      if (this.record.id) {
        prepend = prepend + this.record.id + ":";
      }
      let prepend_buffer = textEncoder.encode(prepend);
      if (this.validation.digest1) {
        this.validation.digest2 = mergeBuffer(prepend_buffer, this.validation.digest1);
        console.timeEnd("doubleDigest");
        resolve();
      } else {
        reject(
          new ValidationError({
            name: "DIGEST_MISSING",
            message: "The digest is missing"
          })
        );
      }
    });
  }
  static getAlgorithmParameters(publicKey, digestAlgorithm, keyAlgorithm) {
    let algorithmParameters;
    let hash = digestAlgorithm;
    if (keyAlgorithm == "rsa") {
      algorithmParameters = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: hash }
      };
    } else if (keyAlgorithm == "ec") {
      let named_curve;
      switch (publicKey.length) {
        case 91:
          named_curve = "P-256";
          break;
        case 120:
          named_curve = "P-384";
          break;
        case 156:
          named_curve = "P-521";
          break;
        default:
          named_curve = "P-256";
          break;
      }
      algorithmParameters = {
        name: "ECDSA",
        hash,
        namedCurve: named_curve
      };
    } else {
      algorithmParameters = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: hash }
      };
    }
    return algorithmParameters;
  }
  static getCryptoKeyLength(key) {
    let keyLength;
    if (key.algorithm.name === "ECDSA") {
      keyLength = parseInt(key.algorithm.namedCurve.replace("P-", ""));
    }
    if (key.algorithm.name === "RSASSA-PKCS1-v1_5") {
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
  static async importCryptoKey(publicKey, algorithmParameters) {
    return new Promise(async (resolve, reject) => {
      const key = await crypto.subtle.importKey("spki", base64ToUint8Array(publicKey), algorithmParameters, true, ["verify"]).catch((error) => {
        reject(
          new ValidationError({
            name: "KEY_IMPORT_ERROR",
            message: "crypto.subtle.importKey couldn't process the data",
            cause: error
          })
        );
      });
      resolve(key);
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
  static async verifySignature(payload, signature, cryptoKey, algorithmParameters) {
    if (cryptoKey.algorithm.name === "ECDSA") {
      signature = convertEcdsaAsn1Signature(signature);
    }
    return crypto.subtle.verify(algorithmParameters, cryptoKey, signature, payload);
  }
};
function base64ToUint8Array(base64) {
  const binaryString = atob(base64);
  const byteArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }
  return byteArray;
}
function hexToUint8Array(hex) {
  if (hex.length % 2 !== 0) {
    throw new ValidationError({
      name: "HEX_STRING",
      message: "Hex string must have an even length"
    });
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
function mergeBuffer(buffer1, buffer2) {
  if (!buffer1) {
    return buffer2;
  } else if (!buffer2) {
    return buffer1;
  }
  const concatenatedBuffer = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  concatenatedBuffer.set(buffer1, 0);
  concatenatedBuffer.set(buffer2, buffer1.byteLength);
  return concatenatedBuffer;
}
function createDate(dateString) {
  const datePattern = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{0,9})/;
  const formattedDateString = dateString.replace(datePattern, "$1-$2-$3T$4:$5:$6.$7Z");
  return new Date(formattedDateString);
}
function convertEcdsaAsn1Signature(input) {
  const elements = readAsn1IntegerSequence(input);
  if (elements.length !== 2) throw new Error("Expected 2 ASN.1 sequence elements");
  let [r, s] = elements;
  if (r[0] === 0 && r.byteLength % 16 == 1) {
    r = r.slice(1);
  }
  if (s[0] === 0 && s.byteLength % 16 == 1) {
    s = s.slice(1);
  }
  if (r.byteLength % 16 == 15) {
    r = new Uint8Array(mergeBuffer(new Uint8Array([0]), r));
  }
  if (s.byteLength % 16 == 15) {
    s = new Uint8Array(mergeBuffer(new Uint8Array([0]), s));
  }
  if (r.byteLength % 16 != 0) throw new Error("unknown ECDSA sig r length error");
  if (s.byteLength % 16 != 0) throw new Error("unknown ECDSA sig s length error");
  return mergeBuffer(r, s);
}
function readAsn1IntegerSequence(input) {
  if (input[0] !== 48) throw new Error("Input is not an ASN.1 sequence");
  const seqLength = input[1];
  const elements = [];
  let current = input.slice(2, 2 + seqLength);
  while (current.length > 0) {
    const tag = current[0];
    if (tag !== 2) throw new Error("Expected ASN.1 sequence element to be an INTEGER");
    const elLength = current[1];
    elements.push(current.slice(2, 2 + elLength));
    current = current.slice(2 + elLength);
  }
  return elements;
}
export {
  SEAL,
  ValidationError,
  mediaAsset
};
