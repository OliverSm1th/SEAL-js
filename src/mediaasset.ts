/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

import { detectMimeType } from './mimetypes';

interface asset {
  data: ArrayBuffer | Uint8Array;
  name: string;
  url: string;
  domain: string;
  size: number;
  mime: string;
  seal_segments?: any[];
}

export class MediaAsset {
  /**
   * Reads chunks of data and processes SEAL segments.
   */
  public static readChunks(asset: asset) {
    // Start timing the readChunks operation
    console.time('readChunks');



    asset.size = asset.data.byteLength
    // Convert the data to a Uint8Array
    asset.data = new Uint8Array(asset.data);


    // Detect the MIME type if it's not available
    if (!asset.mime) {
      asset.mime = detectMimeType(asset.data);
    }

    // scan only the first and last 64kB if file > 64kB
    // probably not working for some formats...
    let skip = false;
    if (asset.data.byteLength - 65536 > 65536) {
      skip = true;
    }

    // Iterate through the data array to find and process SEAL segments
    for (let i = 0; i < asset.data.length; i++) {
      if (i > 65536 && skip === true) {
        //Moving pointer to the last 64kB
        i = asset.data.byteLength - 65536;
        skip = false;
      }

      // Detect the start of a SEAL segment "<seal " (hex: 3C 73 65 61 6C 20)
      if (
        (asset.data[i] == 0x3c &&
          asset.data[i + 1] == 0x73 &&
          asset.data[i + 2] == 0x65 &&
          asset.data[i + 3] == 0x61 &&
          asset.data[i + 4] == 0x6c) ||
        // Detect the start of a SEAL segment "<?seal " (hex: 3C 3F 73 65 61 6C 20)
        (asset.data[i] == 0x3c &&
          asset.data[i + 1] == 0x3f &&
          asset.data[i + 2] == 0x73 &&
          asset.data[i + 3] == 0x65 &&
          asset.data[i + 4] == 0x61 &&
          asset.data[i + 5] == 0x6c) ||
        // Detect the start of a SEAL segment "&lt;seal " (hex: 26 6C 74 3B 73 65 61 6C 20)
        (asset.data[i] == 0x26 &&
          asset.data[i + 1] == 0x6c &&
          asset.data[i + 2] == 0x74 &&
          asset.data[i + 3] == 0x3b &&
          asset.data[i + 4] == 0x73 &&
          asset.data[i + 5] == 0x65)
      ) {
        const sealStart = i;
        let continueReading = true;

        // Continue until the end of the SEAL segment "/>" (hex: 2F 3E) or "?>" (hex: 3F 3E) or "/&gt" (hex: 2F 26 67 74)
        while (continueReading) {
          if (
            (asset.data[i] == 0x2f && asset.data[i + 1] == 0x3e) ||
            (asset.data[i] == 0x3f && asset.data[i + 1] == 0x3e) ||
            (asset.data[i] == 0x2f && asset.data[i + 1] == 0x26 && asset.data[i + 2] == 0x67 && asset.data[i + 3] == 0x74)
          ) {
            continueReading = false;
          }
          i++;
        }

        // Decode the SEAL segment and add it to seal_segments
        const textDecoder = new TextDecoder();
        const sealString = textDecoder.decode(asset.data.slice(sealStart, i + 1)).replace(/\\/gm, '');

        if (!asset.seal_segments) {
          asset.seal_segments = [];
        }

        asset.seal_segments.push({
          string: sealString,
          signature_end: i - 2,
        });
      }
    }

    // End timing the readChunks operation
    console.timeEnd('readChunks');
    return asset;
  }

  /**
   * Assembles a data buffer based on a list of ranges.
   *
   * @param ranges - An array of tuples, each representing the start and end positions of a range.
   * @returns A new Uint8Array that contains the assembled data from the specified ranges.
   */
  public static assembleBuffer(asset: asset, ranges: [number, number][]): Uint8Array {
    // Calculate the total length required for the assembled buffer
    const totalLength = ranges.reduce((sum, [start, end]) => sum + (end - start), 0);
    const assembledBuffer = new Uint8Array(totalLength);

    // Initialize the current position in the assembled buffer
    let currentPosition = 0;

    // Iterate through each range to copy data slices into the assembled buffer
    ranges.forEach(([start, end]) => {
      // Slice the data from the current range
      const dataSlice = asset.data.slice(start, end);

      // Set the sliced data into the assembled buffer at the current position
      assembledBuffer.set(new Uint8Array(dataSlice), currentPosition);

      // Update the current position in the assembled buffer
      currentPosition += dataSlice.byteLength;
    });

    // Return the assembled data buffer
    return assembledBuffer;
  }


  /**
   * Converts a file to an asset.
   *
   * @param {File} file - The file to convert.
   * @returns {Promise<asset>} - A promise that resolves to an asset.
   */
  public static async fileToAsset(file: File): Promise<asset> {
    // Initialize the asset with default properties
    let seal_asset: any = {
      url: 'localhost',
      domain: 'localhost',
      name: file.name,
    };

    // Get the media as a blob and arrayBuffer
    seal_asset.blob = new Blob([file], { type: file.type });
    seal_asset.data = await seal_asset.blob.arrayBuffer();
    seal_asset.mime = seal_asset.blob.type;

    // Detect the MIME type if it's not available
    if (seal_asset.mime.length === 0) {
      seal_asset.mime = detectMimeType(seal_asset.data);
    }

    // Get the size of the asset
    seal_asset.size = seal_asset.blob.size;

    // Create a URL for the asset based on the MIME type
    if (seal_asset.mime.includes('image')) {
      seal_asset.url = URL.createObjectURL(seal_asset.blob);
    } else if (seal_asset.mime.includes('audio') || seal_asset.mime.includes('video')) {
      seal_asset.url = URL.createObjectURL(seal_asset.blob);
    }

    return seal_asset as asset;
  }

  /**
   * Converts a URL to an asset.
   *
   * @param {string} url - The URL to convert.
   * @returns {Promise<asset>} - A promise that resolves to an asset.
   */
  public static async UrlToAsset(url: string): Promise<asset> {
    // Initialize the asset with the given URL
    let seal_asset: any = {
      url: url,
    };

    try {
      // Parse the URL to extract the domain
      let newUrl = new URL(seal_asset.url);
      seal_asset.domain = newUrl.hostname;
    } catch (err) {
      throw new Error('Not an url');
    }

    // Extract the name part of the URL
    seal_asset.name = (seal_asset.url.match(/^\w+:(\/+([^\/#?\s]+)){2,}(#|\?|$)/) || [])[2] || '';

    try {
      // Fetch the media from the URL
      const response = await fetch(seal_asset.url);

      // Ensure the fetch was successful
      if (!response.ok) {
        throw new Error('Failed to fetch media');
      }

      // Get the media as a blob and arrayBuffer
      seal_asset.blob = await response.blob();
      seal_asset.data = await seal_asset.blob.arrayBuffer();
      seal_asset.mime = seal_asset.blob.type;

      // Get the size of the asset
      seal_asset.size = seal_asset.blob.size;

      // Detect the MIME type if it's not available
      if (seal_asset.mime.length === 0) {
        seal_asset.mime = detectMimeType(seal_asset.data);
      }
    } catch (error: any) {
      throw new Error(error);
    }

    return seal_asset as asset;
  }
}
