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
  MediaAsset: () => MediaAsset
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
var MediaAsset = class {
  /**
   * Reads chunks of data and processes SEAL segments.
   */
  static readChunks(asset) {
    console.time("readChunks");
    asset.size = asset.data.byteLength;
    const data = new Uint8Array(asset.data);
    if (!asset.mime) {
      asset.mime = detectMimeType(data);
    }
    let skip = false;
    if (data.byteLength - 65536 > 65536) {
      skip = true;
    }
    for (let i = 0; i < data.length; i++) {
      if (i > 65536 && skip === true) {
        i = asset.data.byteLength - 65536;
        skip = false;
      }
      if (data[i] == 60 && data[i + 1] == 115 && data[i + 2] == 101 && data[i + 3] == 97 && data[i + 4] == 108 || // Detect the start of a SEAL segment "<?seal " (hex: 3C 3F 73 65 61 6C 20)
      data[i] == 60 && data[i + 1] == 63 && data[i + 2] == 115 && data[i + 3] == 101 && data[i + 4] == 97 && data[i + 5] == 108 || // Detect the start of a SEAL segment "&lt;seal " (hex: 26 6C 74 3B 73 65 61 6C 20)
      data[i] == 38 && data[i + 1] == 108 && data[i + 2] == 116 && data[i + 3] == 59 && data[i + 4] == 115 && data[i + 5] == 101) {
        const sealStart = i;
        let continueReading = true;
        while (continueReading) {
          if (data[i] == 47 && data[i + 1] == 62 || data[i] == 63 && data[i + 1] == 62 || data[i] == 47 && data[i + 1] == 38 && data[i + 2] == 103 && data[i + 3] == 116) {
            continueReading = false;
          }
          i++;
        }
        const textDecoder2 = new TextDecoder();
        const sealString = textDecoder2.decode(data.slice(sealStart, i + 1)).replace(/\\/gm, "");
        if (!asset.seal_segments) {
          asset.seal_segments = [];
        }
        asset.seal_segments.push({
          string: sealString,
          signature_end: i - 2
        });
      }
    }
    asset.data = data;
    console.timeEnd("readChunks");
    return asset;
  }
  /**
   * Assembles a data buffer based on a list of ranges.
   *
   * @param ranges - An array of tuples, each representing the start and end positions of a range.
   * @returns A new Uint8Array that contains the assembled data from the specified ranges.
   */
  static assembleBuffer(asset, ranges) {
    const totalLength = ranges.reduce((sum, [start, end]) => sum + (end - start), 0);
    const assembledBuffer = new Uint8Array(totalLength);
    let currentPosition = 0;
    ranges.forEach(([start, end]) => {
      const dataSlice = asset.data.slice(start, end);
      assembledBuffer.set(new Uint8Array(dataSlice), currentPosition);
      currentPosition += dataSlice.byteLength;
    });
    return assembledBuffer;
  }
  /**
   * Converts a file to an asset.
   *
   * @param {File} file - The file to convert.
   * @returns {Promise<asset>} - A promise that resolves to an asset.
   */
  static async fileToAsset(file) {
    let seal_asset = {
      url: "localhost",
      domain: "localhost",
      name: file.name
    };
    seal_asset.blob = new Blob([file], { type: file.type });
    seal_asset.data = await seal_asset.blob.arrayBuffer();
    seal_asset.mime = seal_asset.blob.type;
    if (seal_asset.mime.length === 0) {
      seal_asset.mime = detectMimeType(seal_asset.data);
    }
    seal_asset.size = seal_asset.blob.size;
    if (seal_asset.mime.includes("image")) {
      seal_asset.url = URL.createObjectURL(seal_asset.blob);
    } else if (seal_asset.mime.includes("audio") || seal_asset.mime.includes("video")) {
      seal_asset.url = URL.createObjectURL(seal_asset.blob);
    }
    return seal_asset;
  }
  /**
   * Converts a URL to an asset.
   *
   * @param {string} url - The URL to convert.
   * @returns {Promise<asset>} - A promise that resolves to an asset.
   */
  static async UrlToAsset(url) {
    let seal_asset = {
      url
    };
    try {
      let newUrl = new URL(seal_asset.url);
      seal_asset.domain = newUrl.hostname;
    } catch (err) {
      throw new Error("Not an url");
    }
    seal_asset.name = (seal_asset.url.match(/^\w+:(\/+([^\/#?\s]+)){2,}(#|\?|$)/) || [])[2] || "";
    try {
      const response = await fetch(seal_asset.url);
      if (!response.ok) {
        throw new Error("Failed to fetch media");
      }
      seal_asset.blob = await response.blob();
      seal_asset.data = await seal_asset.blob.arrayBuffer();
      seal_asset.mime = seal_asset.blob.type;
      seal_asset.size = seal_asset.blob.size;
      if (seal_asset.mime.length === 0) {
        seal_asset.mime = detectMimeType(seal_asset.data);
      }
    } catch (error) {
      throw new Error(error);
    }
    return seal_asset;
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  MediaAsset
});
