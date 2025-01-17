/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

const textDecoder = new TextDecoder();
// Common MIME types based on magic numbers (file signatures)
// TODO clean up, add offset, source mostly https://en.wikipedia.org/wiki/List_of_file_signatures
const mimeTypes: { [key: string]: string } = {
  dcdc: 'application/cpl+xml',
  '1f8b08': 'application/gzip',
  '25504446': 'application/pdf',
  '7b5c72746631': 'application/rtf',
  '526172211A0700': 'application/vnd.rar',
  '526172211a070100': 'application/vnd.rar',
  '425a68': 'application/x-bzip2',
  '7573746172003030': 'application/x-tar',
  '7573746172202000': 'application/x-tar',
  '504b0304': 'application/zip',
  '504b0506': 'application/zip',
  '504b0708': 'application/zip',
  '2321414d52': 'audio/AMR',
  '2e736e64': 'audio/basic',
  '646e732e': 'audio/basic',
  '4d546864': 'audio/midi',
  '667479704d344120': 'audio/mp4',
  fffb: 'audio/mp3',
  fff3: 'audio/mp3',
  fff2: 'audio/mp3',
  ffe3: 'audio/mp3',
  '494433': 'audio/mp3',
  fff1: 'audio/aac',
  fff9: 'audio/aac',
  '57415645': 'audio/wav',
  '464f524d00': 'audio/x-aiff',
  '664c6143': 'audio/x-flac',
  '424d': 'image/bmp',
  '4449434D': 'image/dcm',
  '47494638': 'image/gif',
  '0000000C6A502020': 'image/jp2',
  ffd8ff: 'image/jpeg',
  '89504e470d0a1a0a': 'image/png',
  '49492a00': 'image/tiff',
  '4d4d002a': 'image/tiff',
  '3c737667': 'image/svg',
  '38425053': 'image/vnd.adobe.photoshop',
  '57454250': 'image/webp',
  '010009000003': 'image/wmf',
  d7cdc69a: 'image/wmf',
  '5035': 'image/x-portable-graymap',
  '5036': 'image/x-portable-pixmap',
  '01da01010003': 'image/x-rgb',
  '67696d7020786366': 'image/x-xcf',
  '0000001466747970336770': 'video/3gpp2',
  '0000002066747970336770': 'video/3gpp2',
  '6674797069736f6d': 'video/mp4',
  '667479704d534e56': 'video/mp4',
  '000000186674797033677035': 'video/mp4',
  '0000001c667479704d534e56012900464d534e566d703432': 'video/mp4',
  '6674797033677035': 'video/mp4',
  '00000018667479706d703432': 'video/mp4',
  '667479706d703432': 'video/mp4',
  ffd8: 'video/mpeg',
  '000001ba': 'video/mpeg',
  '4F676753': 'video/ogg',
  '1466747970717420': 'video/quicktime',
  '6674797071742020': 'video/quicktime',
  '6d6f6f76': 'video/quicktime',
  '20667479704d3456': 'video/x-flv',
  '464c5601': 'video/x-flv',
  '1a45dfa3': 'video/x-matroska',
};

export function detectMimeType(fileBytes: Uint8Array): string {
  // Convert the first few bytes to a hexadecimal string for easy comparison
  const bytesHex = Array.from(fileBytes.slice(0, 16))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  // Check for matching MIME type
  for (const [signature, mimeType] of Object.entries(mimeTypes)) {
    if (bytesHex.includes(signature)) {
      return mimeType;
    }
  }

  // backup
  const textCharactersRegex = /^[\x09\x0A\x0D\x20-\x7E\x80-\xFF]*$/m;
  let string = textDecoder.decode(fileBytes.slice(1, 32));

  if (string.includes('mp4')) {
    return 'video/mp4';
  }
  if (string.includes('heic')) {
    return 'image/heif';
  }
  if (string.includes('jumb')) {
    return 'application/c2pa';
  }
  if (string.includes('DICM')) {
    return 'image/dcm';
  }
  if (textCharactersRegex.test(string)) {
    if (string.includes('DOCTYPE') && string.includes('html')) {
      return 'text/html';
    }
    if (string.includes('DOCTYPE') && string.includes('svg')) {
      return 'image/svg';
    } else {
      return 'text/plain';
    }
  }

  // dumphex(fileBytes); //debug

  // Return 'unknown' if no match is found
  return 'unknown';
}

/**
 * Dumps the content of a byte array in a formatted table with offset, decimal, ASCII, and hexadecimal representations.
 * Outputs data in batches of 8 bytes.
 *
 * @param b - The byte array to be dumped.
 * @param options - The option to select output format ('decimal', 'ascii', 'hex', or 'all').
 */
function dumphex(b: Uint8Array, options: 'decimal' | 'ascii' | 'hex' | 'all' = 'all'): void {
  // Initialize a 2D array for storing offset, decimal, ASCII, and hex representations
  let dump: (string | number)[][] = [[], [], [], []];

  // Helper function to log the current dump table
  const logTable = () => {
    switch (options) {
      case 'decimal':
        console.table({ Offset: dump[0], Decimal: dump[1] });
        break;
      case 'ascii':
        console.table({ Offset: dump[0], ASCII: dump[2] });
        break;
      case 'hex':
        console.table({ Offset: dump[0], Hex: dump[3] });
        break;
      case 'all':
      default:
        console.table({
          Offset: dump[0],
          Decimal: dump[1],
          ASCII: dump[2],
          Hex: dump[3],
        });
        break;
    }
  };

  // Iterate over each byte in the array in batches of 8 bytes
  for (let i = 0; i < b.length; i++) {
    dump[0].push(i.toString().padStart(2, '0')); // Offset
    dump[1].push(b[i]); // Decimal value
    dump[2].push(String.fromCharCode(b[i])); // ASCII character
    dump[3].push('0x' + b[i].toString(16).padStart(2, '0').toUpperCase()); // Hexadecimal value

    // If we've reached a batch of 8 bytes, log the current table and reset
    if ((i + 1) % 8 === 0 || i === b.length - 1) {
      logTable();
      dump = [[], [], [], []]; // Reset for the next batch
    }
  }
}
