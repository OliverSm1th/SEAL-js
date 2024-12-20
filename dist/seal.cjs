"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/seal.ts
var seal_exports = {};
__export(seal_exports, {
  SEAL: () => SEAL,
  ValidationError: () => ValidationError,
  mediaAsset: () => mediaAsset
});
module.exports = __toCommonJS(seal_exports);

// src/mimetypes.ts
var textDecoder = new TextDecoder();
var mimeTypes = {
  dcdc: "application/cpl+xml",
  "1f8b08": "application/gzip",
  "25504446": "application/pdf",
  "7b5c72746631": "application/rtf",
  "526172211A0700": "application/vnd.rar",
  "526172211a070100": "application/vnd.rar",
  "425a68": "application/x-bzip2",
  "7573746172003030": "application/x-tar",
  "7573746172202000": "application/x-tar",
  "504b0304": "application/zip",
  "504b0506": "application/zip",
  "504b0708": "application/zip",
  "2321414d52": "audio/AMR",
  "2e736e64": "audio/basic",
  "646e732e": "audio/basic",
  "4d546864": "audio/midi",
  "667479704d344120": "audio/mp4",
  fffb: "audio/mp3",
  fff3: "audio/mp3",
  fff2: "audio/mp3",
  ffe3: "audio/mp3",
  "494433": "audio/mp3",
  fff1: "audio/aac",
  fff9: "audio/aac",
  "57415645": "audio/wav",
  "464f524d00": "audio/x-aiff",
  "664c6143": "audio/x-flac",
  "424d": "image/bmp",
  "4449434D": "image/dcm",
  "47494638": "image/gif",
  "0000000C6A502020": "image/jp2",
  ffd8ff: "image/jpeg",
  "89504e470d0a1a0a": "image/png",
  "49492a00": "image/tiff",
  "4d4d002a": "image/tiff",
  "3c737667": "image/svg",
  "38425053": "image/vnd.adobe.photoshop",
  "57454250": "image/webp",
  "010009000003": "image/wmf",
  d7cdc69a: "image/wmf",
  "5035": "image/x-portable-graymap",
  "5036": "image/x-portable-pixmap",
  "01da01010003": "image/x-rgb",
  "67696d7020786366": "image/x-xcf",
  "0000001466747970336770": "video/3gpp2",
  "0000002066747970336770": "video/3gpp2",
  "6674797069736f6d": "video/mp4",
  "667479704d534e56": "video/mp4",
  "000000186674797033677035": "video/mp4",
  "0000001c667479704d534e56012900464d534e566d703432": "video/mp4",
  "6674797033677035": "video/mp4",
  "00000018667479706d703432": "video/mp4",
  "667479706d703432": "video/mp4",
  ffd8: "video/mpeg",
  "000001ba": "video/mpeg",
  "4F676753": "video/ogg",
  "1466747970717420": "video/quicktime",
  "6674797071742020": "video/quicktime",
  "6d6f6f76": "video/quicktime",
  "20667479704d3456": "video/x-flv",
  "464c5601": "video/x-flv",
  "1a45dfa3": "video/x-matroska"
};
function detectMimeType(fileBytes) {
  const bytesHex = Array.from(fileBytes.slice(0, 16)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  for (const [signature, mimeType] of Object.entries(mimeTypes)) {
    if (bytesHex.includes(signature)) {
      return mimeType;
    }
  }
  const textCharactersRegex = /^[\x09\x0A\x0D\x20-\x7E\x80-\xFF]*$/m;
  let string = textDecoder.decode(fileBytes.slice(1, 32));
  if (string.includes("mp4")) {
    return "video/mp4";
  }
  if (string.includes("heic")) {
    return "image/heif";
  }
  if (string.includes("jumb")) {
    return "application/c2pa";
  }
  if (string.includes("DICM")) {
    return "image/dcm";
  }
  if (textCharactersRegex.test(string)) {
    if (string.includes("DOCTYPE") && string.includes("html")) {
      return "text/html";
    }
    if (string.includes("DOCTYPE") && string.includes("svg")) {
      return "image/svg";
    } else {
      return "text/plain";
    }
  }
  return "unknown";
}

// src/mediaasset.ts
var textDecoder2 = new TextDecoder();
var mediaAsset = class {
  constructor(data, filename) {
    this.data = data;
    this.filename = filename;
    this.filename = filename;
    this.readChunks();
    console.log(`[${filename}](${this.mimeType})`);
  }
  mimeType = "image/jpeg";
  seal_segments = [];
  getDataLength() {
    return this.data.byteLength;
  }
  /**
   * Reads chunks of data and processes SEAL segments.
   */
  readChunks() {
    console.time("readChunks");
    const dataArray = new Uint8Array(this.data);
    this.data = dataArray;
    this.mimeType = detectMimeType(dataArray.slice(0, 140));
    let skip = false;
    if (this.getDataLength() - 65536 > 65536) {
      skip = true;
    }
    for (let i = 0; i < dataArray.length; i++) {
      if (i > 65536 && skip === true) {
        i = this.getDataLength() - 65536;
        skip = false;
      }
      if (dataArray[i] == 60 && dataArray[i + 1] == 115 && dataArray[i + 2] == 101 && dataArray[i + 3] == 97 && dataArray[i + 4] == 108 || // Detect the start of a SEAL segment "<?seal " (hex: 3C 3F 73 65 61 6C 20)
      dataArray[i] == 60 && dataArray[i + 1] == 63 && dataArray[i + 2] == 115 && dataArray[i + 3] == 101 && dataArray[i + 4] == 97 && dataArray[i + 5] == 108 || // Detect the start of a SEAL segment "&lt;seal " (hex: 26 6C 74 3B 73 65 61 6C 20)
      dataArray[i] == 38 && dataArray[i + 1] == 108 && dataArray[i + 2] == 116 && dataArray[i + 3] == 59 && dataArray[i + 4] == 115 && dataArray[i + 5] == 101) {
        const sealStart = i;
        let continueReading = true;
        while (continueReading) {
          if (dataArray[i] == 47 && dataArray[i + 1] == 62 || dataArray[i] == 63 && dataArray[i + 1] == 62 || dataArray[i] == 47 && dataArray[i + 1] == 38 && dataArray[i + 2] == 103 && dataArray[i + 3] == 116) {
            continueReading = false;
          }
          i++;
        }
        const sealString = textDecoder2.decode(dataArray.slice(sealStart, i + 1));
        this.seal_segments.push({ string: sealString, signature_end: i - 2 });
      }
    }
    console.timeEnd("readChunks");
  }
  dumpInfo() {
    console.log(this);
  }
  /**
   * Assembles a data buffer based on a list of ranges.
   *
   * @param ranges - An array of tuples, each representing the start and end positions of a range.
   * @returns A new Uint8Array that contains the assembled data from the specified ranges.
   */
  assembleBuffer(ranges) {
    const totalLength = ranges.reduce((sum, [start, end]) => sum + (end - start), 0);
    const assembledBuffer = new Uint8Array(totalLength);
    let currentPosition = 0;
    ranges.forEach(([start, end]) => {
      const dataSlice = this.data.slice(start, end);
      assembledBuffer.set(new Uint8Array(dataSlice), currentPosition);
      currentPosition += dataSlice.byteLength;
    });
    return assembledBuffer;
  }
};

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
   * Imports a public key from a PEM-encoded string.
   *
   * @param pem - The PEM-encoded public key.
   * @param keyAlgorithm - The key algorithm ('rsa' or 'ec').
   * @returns A promise that resolves to the imported CryptoKey.
   */
  static async importPublicKey(pem, keyAlgorithm) {
    console.time("importPublicKey");
    return new Promise(async (resolve, reject) => {
      let algorithmParams;
      if (keyAlgorithm === "rsa") {
        algorithmParams = {
          name: "RSASSA-PKCS1-v1_5",
          hash: {
            name: "SHA-256"
            // TODO: Add handling for different key sizes
          }
        };
      } else if (keyAlgorithm === "ec") {
        algorithmParams = {
          name: "ECDSA",
          namedCurve: "P-256"
          // TODO: Replace with the appropriate curve name
        };
      }
      const keyData = base64ToArrayBuffer(pem);
      await crypto.subtle.importKey(
        "spki",
        // The format of the key
        keyData,
        // The key data
        algorithmParams,
        // The algorithm parameters
        true,
        // Whether the key is extractable
        ["verify"]
        // The key usage
      ).then((publicKey) => {
        resolve(publicKey);
      }).catch((error) => {
        if (keyAlgorithm === "rsa") {
          reject("RSA: " + error.message);
        }
        reject(error.message);
        if (keyAlgorithm === "ec") {
          reject("EC: " + error.message);
        }
      });
      console.timeEnd("importPublicKey");
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
    return new Promise(async (resolve) => {
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
              console.error("ranges start error");
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
              console.error("ranges start error");
              break;
          }
          stop = stop + add + sub;
          this.validation.digest_ranges?.push([start, stop]);
          this.validation.digest_summary = `${show_range_start} to ${show_range_stop}`;
        });
        this.validation.digest1 = await _SEAL._digest(asset.assembleBuffer(this.validation.digest_ranges), this.record.da);
        console.timeEnd("digest");
        resolve();
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
                this.validation.signature = this.validation.signature.replace(format + ":", "");
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
            this.validation.signature = hexToArrayBuffer(this.validation.signature);
          }
          if (this.validation.signature_encoding == "base64") {
            this.validation.signature = base64ToArrayBuffer(this.validation.signature);
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
      let prepend_buffer = textEncoder.encode(prepend).buffer;
      if (this.validation.digest1) {
        this.validation.digest2 = concatArrayBuffers(prepend_buffer, this.validation.digest1);
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
  static async validateSig(asset) {
    console.time("validateSig");
    return new Promise(async (resolve, reject) => {
      this.validation = {};
      let public_key;
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
      if (this.public_keys[this.record.d][this.record.ka]) {
        if (!this.public_keys[this.record.d][this.record.ka].imported_key) {
          public_key = this.public_keys[this.record.d][this.record.ka].imported_key = await this.importPublicKey(
            this.public_keys[this.record.d][this.record.ka].p,
            this.public_keys[this.record.d][this.record.ka].ka
          ).catch((error) => {
            return reject(
              new ValidationError({
                name: "KEY_IMPORT_ERROR",
                message: "The Public key couldn't be imported",
                cause: error
              })
            );
          });
        } else {
          console.debug("CACHED ---importPublicKey");
          public_key = this.public_keys[this.record.d][this.record.ka].imported_key;
        }
      }
      await _SEAL.digest(asset);
      await _SEAL.doubleDigest();
      let algorithm;
      let hash;
      switch (this.record.da) {
        case "sha256":
          hash = "SHA-256";
          break;
        case "sha384":
          hash = "SHA-384";
          break;
        case "sha512":
          hash = "SHA-512";
          break;
        case "sha1":
          hash = "SHA-1";
          break;
        default:
          hash = "SHA-256";
          break;
      }
      if (this.record.ka == "rsa") {
        algorithm = "RSASSA-PKCS1-v1_5";
      }
      if (this.record.ka == "ec") {
        algorithm = {
          name: "ECDSA",
          hash: { name: hash }
        };
      }
      if (this.validation.digest2 && this.validation.signature && public_key) {
        await crypto.subtle.verify(algorithm, public_key, this.validation.signature, this.validation.digest2).then(async (result) => {
          console.timeEnd("validateSig");
          this.validation.digest2 = await _SEAL._digest(this.validation.digest2, this.record.da);
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
          let summary = `${result_string}
Signature Algorithm: ${this.record.ka.toUpperCase()}, ${256 * 8} bits
Digest Algorithm: ${this.record.da}
Digest: ${Array.from(new Uint8Array(this.validation.digest1)).map((bytes) => bytes.toString(16).padStart(2, "0")).join("")}
Double Digest: ${Array.from(new Uint8Array(this.validation.digest2)).map((bytes) => bytes.toString(16).padStart(2, "0")).join("")}
Signed Bytes: ${this.validation.digest_ranges}
Signature Spans: ${this.validation.digest_summary}
Signed By: ${this.record.d} for user ${this.record.id}
Copyright: ${this.record.copyright}
Comment: ${this.record.info}`;
          resolve({ result, summary });
        }).catch((error) => {
          reject(
            new ValidationError({
              name: "VALIDATION_GENERAL_ERROR",
              message: "crypto.subtle.verify couldn't process the data",
              cause: error
            })
          );
        });
      } else {
        reject(
          new ValidationError({
            name: "VALIDATION_MISSING_PARAMETERS",
            message: "Double Digest or Signature or Public key is missing"
          })
        );
      }
    });
  }
  /**
   *
   *
   * @static
   * @param {ArrayBuffer} data
   * @param {String} [da]
   * @return {*}  {Promise<ArrayBuffer>}
   * @memberof SEAL
   */
  static async _digest(data, da) {
    return new Promise(async (resolve) => {
      let algorithm;
      switch (da) {
        case "sha256":
          algorithm = "SHA-256";
          break;
        case "sha384":
          algorithm = "SHA-384";
          break;
        case "sha512":
          algorithm = "SHA-512";
          break;
        case "sha1":
          algorithm = "SHA-1";
          break;
        default:
          algorithm = "SHA-256";
          break;
      }
      resolve(await crypto.subtle.digest(algorithm, data));
    });
  }
};
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const byteArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }
  return byteArray.buffer;
}
function hexToArrayBuffer(hex) {
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
  return bytes.buffer;
}
function concatArrayBuffers(buffer1, buffer2) {
  if (!buffer1) {
    return buffer2;
  } else if (!buffer2) {
    return buffer1;
  }
  const concatenatedBuffer = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  concatenatedBuffer.set(new Uint8Array(buffer1), 0);
  concatenatedBuffer.set(new Uint8Array(buffer2), buffer1.byteLength);
  return concatenatedBuffer.buffer;
}
function createDate(dateString) {
  const datePattern = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{0,9})/;
  const formattedDateString = dateString.replace(datePattern, "$1-$2-$3T$4:$5:$6.$7Z");
  return new Date(formattedDateString);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  SEAL,
  ValidationError,
  mediaAsset
});
