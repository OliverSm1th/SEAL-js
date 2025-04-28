import {
  detectMimeType
} from "./chunk-APGEQWFO.js";

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
        const textDecoder = new TextDecoder();
        const sealString = textDecoder.decode(data.slice(sealStart, i + 1)).replace(/\\/gm, "");
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

export {
  MediaAsset
};
