import {
  MediaAsset
} from "./chunk-EF6CUMPN.js";
import "./chunk-APGEQWFO.js";

// src/doh.ts
var DoH = class {
  /**
   * getDNSTXTRecords(): Given a hostname and a DoH provider, get TXT records from DNS.
   * Returns: TXT records.
   *
   * @static
   * @param {string} hostname
   * @param {string} [doh_api='https://mozilla.cloudflare-dns.com/dns-query']
   * @return {*}  {Promise<string[]>}
   * @memberof SEAL
   */
  static async getDNSTXTRecords(hostname, doh_api = "https://mozilla.cloudflare-dns.com/dns-query") {
    console.time("getDNS_" + doh_api);
    return new Promise(async (resolve, reject) => {
      let fetchUrl;
      fetchUrl = `${doh_api}?name=${hostname}&type=TXT`;
      await fetch(fetchUrl, {
        method: "GET",
        headers: {
          accept: "application/dns-json"
        }
      }).then((response) => {
        if (response.ok) {
          return response.json();
        }
        throw new Error("Unexpected server response, code: " + response.status);
      }).then((data) => {
        if (data.Answer) {
          let records = [];
          data.Answer.forEach((record) => {
            let keyObject = {};
            const keyElements = record.data.replace(/".{0,1}"/g, "").replace(/"/g, "").split(" ");
            keyElements.forEach((element) => {
              const keyValuePair = element.split("=");
              keyObject[keyValuePair[0]] = keyValuePair[1];
            });
            records.push(keyObject);
          });
          resolve(records);
        } else {
          throw new Error("No Answer field from DoH");
        }
      }).catch((error) => {
        reject(error);
      });
      console.timeEnd("getDNS_" + doh_api);
    });
  }
};

// src/utils.ts
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
    throw new Error("Hex string must have an even length");
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
  let accuracy;
  let accuracy_chuncks = dateString.split(".");
  if (accuracy_chuncks[1]) {
    dateString = accuracy_chuncks[0];
    accuracy = accuracy_chuncks[1];
  } else {
    accuracy = "000";
  }
  const datePattern = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
  const formattedDateString = dateString.replace(datePattern, "$1-$2-$3T$4:$5:$6." + accuracy + "Z");
  return new Date(formattedDateString);
}

// src/crypto.ts
var Crypto = class _Crypto {
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
        reject({ message: error });
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
      signature = _Crypto.convertEcdsaAsn1Signature(signature);
    }
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
  static convertEcdsaAsn1Signature(input) {
    const elements = _Crypto.readAsn1IntegerSequence(input);
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
  /**
   * Reads an ASN.1 integer sequence from the input Uint8Array.
   *
   * @param {Uint8Array} input - The input buffer containing the ASN.1 sequence.
   * @returns {Uint8Array[]} - An array of Uint8Array elements representing the integers in the sequence.
   * @throws {Error} - If the input is not a valid ASN.1 sequence or if an element is not an INTEGER.
   */
  static readAsn1IntegerSequence(input) {
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
};

// src/seal.ts
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
    if (asset.seal_segments[0].string.match(/&quot;/g)) {
      asset.seal_segments[0].signature_end = asset.seal_segments[0].signature_end - 5;
    }
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
  /**
   * Validates the digital signature of the given asset using the SEAL protocol.
   *
   * @param {any} asset - The asset containing the data to validate.
   * @param {boolean} [verbose=false] - Whether to provide verbose output.
   * @returns {Promise<{ result: boolean, summary: string }>} - A promise that resolves to an object containing the validation result and summary.
   */
  static async validateSig(asset, verbose = false) {
    return new Promise(async (resolve, reject) => {
      let result_summary = {};
      asset = MediaAsset.readChunks(asset);
      if (!asset.seal_segments) {
        result_summary.message = "\u{1F622} No SEAL signatures found.";
        return resolve(result_summary);
      }
      this.validation = {
        digest_summary: "",
        signature_bytes: new Uint8Array(),
        signature_encoding: "",
        verbose,
        doh_api: "https://mozilla.cloudflare-dns.com/dns-query"
      };
      _SEAL.parse(asset);
      let domain = this.record.d;
      if (!this.public_keys[domain]) {
        let TXTRecords = await DoH.getDNSTXTRecords(domain, this.validation.doh_api).catch((error) => {
          return reject(
            new ValidationError({
              name: "DNS_LOOKUP",
              message: "Querying DoH " + this.record.d + " DNS for a TXT record failed",
              cause: error.message
            })
          );
        });
        if (!TXTRecords) {
          return;
        }
        TXTRecords.forEach((record) => {
          if (record.ka && record.seal && record.p) {
            if (!this.public_keys[domain]) {
              this.public_keys[domain] = {};
            }
            if (record.ka === "rsa") {
              this.public_keys[domain].rsa = record.p;
            }
            if (record.ka === "ec") {
              this.public_keys[domain].ec = record.p;
            }
          }
        });
        if (!this.public_keys[domain]) {
          return reject(
            new ValidationError({
              name: "DNS_LOOKUP",
              message: "Public key not found or corrupted",
              cause: JSON.stringify(TXTRecords)
            })
          );
        }
      }
      await _SEAL.digest(asset).catch((error) => {
        reject(
          new ValidationError({
            name: "DIGEST_ERROR",
            message: "Digest can not be processed",
            cause: error.message
          })
        );
      });
      await _SEAL.doubleDigest().catch((error) => {
        reject(
          new ValidationError({
            name: "DIGEST_ERROR",
            message: "doubleDigest can not be processed",
            cause: error.message
          })
        );
      });
      let algorithmParameters = Crypto.getAlgorithmParameters(
        this.public_keys[this.record.d][this.record.ka],
        this.record.da,
        this.record.ka
      );
      let cryptoKey = await Crypto.importCryptoKey(this.public_keys[this.record.d][this.record.ka], algorithmParameters).catch((error) => {
        reject(
          new ValidationError({
            name: "KEY_IMPORT_ERROR",
            message: "crypto.subtle.importKey couldn't process the data",
            cause: error.message
          })
        );
      });
      if (this.validation.digest2 && this.validation.signature && cryptoKey) {
        console.time("verifySignature");
        let result = await Crypto.verifySignature(
          this.validation.digest2,
          this.validation.signature_bytes,
          cryptoKey,
          algorithmParameters
        ).catch((error) => {
          return reject(
            new ValidationError({
              name: "SIGNATURE_VERIFY_ERROR",
              message: "The signature can not be verified",
              cause: error.message
            })
          );
        });
        console.timeEnd("verifySignature");
        if (result === true) {
          result_summary.message = `\u2705 SEAL record #1 is valid.`;
          result_summary.valid = true;
        } else {
          result_summary.message = `\u26D4 SEAL record #1 is NOT valid.`;
          result_summary.valid = false;
        }
        result_summary.filename = asset.name;
        result_summary.filemime = asset.mime;
        if (this.validation.verbose) {
          result_summary.filesize = asset.size - 1;
          result_summary.filedomain = asset.domain;
          result_summary.doh_api = this.validation.doh_api;
          result_summary.domain = this.record.d;
          if (this.validation.signature_date) {
            result_summary.signed_on = createDate(this.validation.signature_date).toISOString();
          }
          result_summary.digest = Array.from(this.validation.digest1).map((bytes) => bytes.toString(16).padStart(2, "0")).join("");
          this.validation.digest2 = new Uint8Array(await crypto.subtle.digest(this.record.da, this.validation.digest2));
          result_summary.double_digest = Array.from(this.validation.digest2).map((bytes) => bytes.toString(16).padStart(2, "0")).join("");
          result_summary.key_algorithm = `${this.record.ka.toUpperCase()}, ${Crypto.getCryptoKeyLength(cryptoKey)} bits`;
          result_summary.digest_algorithm = this.record.da;
          result_summary.key_base64 = this.public_keys[this.record.d][this.record.ka];
          let digest_ranges_summary = [];
          this.validation.digest_ranges?.forEach((digest_range) => {
            digest_ranges_summary.push(digest_range[0] + "-" + (digest_range[1] - 1));
          });
          result_summary.signed_bytes = digest_ranges_summary;
          result_summary.spans = this.validation.digest_summary;
          result_summary.user = this.record.id;
          if (this.record.copyright) {
            result_summary.copyright = this.record.copyright;
          }
          if (this.record.info) {
            result_summary.comment = this.record.info;
          }
        }
        resolve(result_summary);
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
   * digest(): Given a file, compute the digest!
   * Computes the digest and stores binary data in @digest1.
   * Stores the byte range in 'digest_range'.
   * Sets 'digest_summary' to store summaries of range
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
              start = asset.size;
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
              return reject(new Error("ranges start error"));
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
              stop = asset.size;
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
              return reject(new Error("ranges stop error"));
          }
          stop = stop + add + sub;
          this.validation.digest_ranges?.push([start, stop]);
          this.validation.digest_summary = `${show_range_start} to ${show_range_stop}`;
        });
        crypto.subtle.digest(this.record.da, MediaAsset.assembleBuffer(asset, this.validation.digest_ranges)).then((digest) => {
          this.validation.digest1 = new Uint8Array(digest);
          console.timeEnd("digest");
          resolve();
        }).catch((error) => {
          reject(error);
        });
      }
    });
  }
  /**
   * If there's a date or id (user_id), then add them to the digest.
   * This uses binary 'digest1', 'id', 'signature_date', and 'da'.
   * Computes the digest and places new data in digest2.
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
                  this.validation.signature_date = this.record.s.substring(0, 14);
                } else {
                  this.validation.signature = this.record.s.substring(16 + accuracy, this.record.s.length);
                  this.validation.signature_date = this.record.s.substring(0, 15 + accuracy);
                }
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
          return reject(error);
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
      const textEncoder = new TextEncoder();
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
};
export {
  SEAL,
  ValidationError
};
