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

// src/mediaasset.ts
var mediaasset_exports = {};
__export(mediaasset_exports, {
  mediaAsset: () => mediaAsset
});
module.exports = __toCommonJS(mediaasset_exports);

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
        const sealString = textDecoder2.decode(dataArray.slice(sealStart, i + 1)).replace(/\\/gm, "");
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  mediaAsset
});
