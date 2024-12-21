import {
  detectMimeType
} from "./chunk-APGEQWFO.js";

// src/mediaasset.ts
var textDecoder = new TextDecoder();
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
        const sealString = textDecoder.decode(dataArray.slice(sealStart, i + 1)).replace(/\\/gm, "");
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

export {
  mediaAsset
};
