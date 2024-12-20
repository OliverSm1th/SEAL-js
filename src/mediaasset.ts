/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

import { detectMimeType } from './mimetypes.js';

interface Asset {
  /**
   * Returns the length of the asset in bytes
   */
  getDataLength(): number;

  /**
   * hold SEAL segments
   */
  seal_segments: any[];

  /**
   * The asset's MIME type
   */
  readonly mimeType: string;
}

const textDecoder = new TextDecoder();

export class mediaAsset implements Asset {
  public mimeType = 'image/jpeg';
  public seal_segments = [];

  constructor(
    protected data: ArrayBuffer,
    protected filename: string,
  ) {
    this.filename = filename;
    this.readChunks();
    console.log(`[${filename}](${this.mimeType})`);
  }

  public getDataLength(): number {
    return this.data.byteLength;
  }

  /**
   * Reads chunks of data and processes SEAL segments.
   */
  private readChunks() {
    // Start timing the readChunks operation
    console.time('readChunks');

    // Convert the data to a Uint8Array and detect the MIME type
    const dataArray: Uint8Array = new Uint8Array(this.data);
    this.data = dataArray;
    this.mimeType = detectMimeType(dataArray.slice(0, 140));

    // scan only the first and last 64kB if file > 64kB
    // probably not working for some formats... TODO mimeType
    let skip = false;
    if (this.getDataLength() - 65536 > 65536) {
      skip = true;
    }

    // Iterate through the data array to find and process SEAL segments
    for (let i = 0; i < dataArray.length; i++) {
      if (i > 65536 && skip === true) {
        i = this.getDataLength() - 65536;
        skip = false;
      }

      // Detect the start of a SEAL segment "<seal " (hex: 3C 73 65 61 6C 20)
      if (
        (dataArray[i] == 0x3c &&
          dataArray[i + 1] == 0x73 &&
          dataArray[i + 2] == 0x65 &&
          dataArray[i + 3] == 0x61 &&
          dataArray[i + 4] == 0x6c) ||
        // Detect the start of a SEAL segment "<?seal " (hex: 3C 3F 73 65 61 6C 20)
        (dataArray[i] == 0x3c &&
          dataArray[i + 1] == 0x3f &&
          dataArray[i + 2] == 0x73 &&
          dataArray[i + 3] == 0x65 &&
          dataArray[i + 4] == 0x61 &&
          dataArray[i + 5] == 0x6c) ||
        // Detect the start of a SEAL segment "&lt;seal " (hex: 26 6C 74 3B 73 65 61 6C 20)
        (dataArray[i] == 0x26 &&
          dataArray[i + 1] == 0x6c &&
          dataArray[i + 2] == 0x74 &&
          dataArray[i + 3] == 0x3b &&
          dataArray[i + 4] == 0x73 &&
          dataArray[i + 5] == 0x65)
      ) {
        const sealStart = i;
        let continueReading = true;

        // Continue until the end of the SEAL segment "/>" (hex: 2F 3E) or "?>" (hex: 3F 3E) or "/&gt" (hex: 2F 26 67 74)
        while (continueReading) {
          if (
            (dataArray[i] == 0x2f && dataArray[i + 1] == 0x3e) ||
            (dataArray[i] == 0x3f && dataArray[i + 1] == 0x3e) ||
            (dataArray[i] == 0x2f && dataArray[i + 1] == 0x26 && dataArray[i + 2] == 0x67 && dataArray[i + 3] == 0x74)
          ) {
            continueReading = false;
          }
          i++;
        }

        // Decode the SEAL segment and add it to seal_segments
        const sealString = textDecoder.decode(dataArray.slice(sealStart, i + 1));
        this.seal_segments.push({ string: sealString, signature_end: i - 2 });
      }
    }

    // End timing the readChunks operation
    console.timeEnd('readChunks');
  }

  public dumpInfo(): any {
    console.log(this);
  }

  /**
   * Assembles a data buffer based on a list of ranges.
   *
   * @param ranges - An array of tuples, each representing the start and end positions of a range.
   * @returns A new Uint8Array that contains the assembled data from the specified ranges.
   */
  public assembleBuffer(ranges: [number, number][]): Uint8Array {
    // Calculate the total length required for the assembled buffer
    const totalLength = ranges.reduce((sum, [start, end]) => sum + (end - start), 0);
    const assembledBuffer = new Uint8Array(totalLength);

    // Initialize the current position in the assembled buffer
    let currentPosition = 0;

    // Iterate through each range to copy data slices into the assembled buffer
    ranges.forEach(([start, end]) => {
      // Slice the data from the current range
      const dataSlice = this.data.slice(start, end);

      // Set the sliced data into the assembled buffer at the current position
      assembledBuffer.set(new Uint8Array(dataSlice), currentPosition);

      // Update the current position in the assembled buffer
      currentPosition += dataSlice.byteLength;
    });

    // Return the assembled data buffer
    return assembledBuffer;
  }
}
