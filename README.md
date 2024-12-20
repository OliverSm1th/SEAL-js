# SEAL-js
- [SEAL-js](#seal-js)
  - [About](#about)
  - [Roadmap and current status](#roadmap-and-current-status)
    - [Overall functionalities](#overall-functionalities)
    - [Image file formats Read Support](#image-file-formats-read-support)
    - [Audio file formats Read Support](#audio-file-formats-read-support)
    - [Video file formats Read Support](#video-file-formats-read-support)
    - [Document formats Read Support](#document-formats-read-support)
    - [Container formats Read Support](#container-formats-read-support)
  - [Usage examples](#usage-examples)
    - [Reading and validating a media](#reading-and-validating-a-media)
    - [Creating a SEAL](#creating-a-seal)
  - [Contributing](#contributing)
  - [License](#license)

## About
`SEAL-js` is a TypeScript implementation of [Secure Evidence Attribution Label (SEAL)](https://github.com/hackerfactor/SEAL) according to [Version 1.1.4, 5-October-2024](https://github.com/hackerfactor/SEAL/blob/master/SPECIFICATION.md).

It should run out of the box in modern browsers as well as Node.js 

## Roadmap and current status

This library is under active development and not fully functional yet. Proceed with caution!

### Overall functionalities

- ✅ Read SEAL metadata
- ✅ DNS record lookup
- ✅ Parse DNS record
- ✅ Parse signature format
- ✅ Compute the digest
- ✅ Compute the Double Digest
- ✅ Hash the digest
- 🚧 Validate the digest **(sha256 RSA only)**
- ❌ Write SEAL metadata
  
### Image file formats Read Support

- ✅ JPEG
- ✅ PNG
- ✅ GIF
- ✅ WEBP
- ✅ HEIC
- 🚧 AVIF
- ✅ PNM/PPM/PGM
- ✅ SVG
- ✅ TIFF
- ✅ DICOM
- ❌ BMP   (no metadata support)
- ❌ FAX   (No. Seriously, just no.)

### Audio file formats Read Support
- ✅ AAC
- 🚧 AVIF
- ✅ M4A
- ✅ MKA
- ✅ MP3
- ✅ MP3+ID3
- ✅ MPEG
- ✅ WAV

### Video file formats Read Support
- ✅ MP4
- 🚧 3GP
- 🚧 AVI
- 🚧 AVIF
- 🚧 HEIF
- 🚧 HEVC
- 🚧 DIVX
- 🚧 MKV
- 🚧 MOV/Quicktime
- ✅ MPEG
- 🚧 WEBM

### Document formats Read Support
- ✅ PDF
- ✅ XML
- ✅ HTML
- ✅ Plain Text
- 🚧 OpenDocument (docx, pptx, etc.)

### Container formats Read Support
- ✅ EXIF  (Nested EXIF records are unsupported due to the ambiguous scope.)
- ✅ XMP (Nested XMP records are unsupported due to the ambiguous scope.)
- 🚧 RIFF 
- 🚧 ISO-BMFF
- ✅ Matroska
- 🚧 ZIP (The OpenDocument formats use ZIP.)

## Usage examples

### Reading and validating a media

Example usage in a Node.js environment:

```typescript
import path from 'path'
import { readFileSync } from 'node:fs';
import { SEAL, mediaAsset } from './dist/seal.js';

if (process.argv.length < 3) {
  console.error('Missing filename');
  process.exit(1);
}

// Read the asset file
const buf = readFileSync(process.argv[2]).buffer;

let asset = new mediaAsset(buf, path.basename(process.argv[2]));

if (asset.seal_segments.length > 0) {
  SEAL.parse(asset);
  console.log(await SEAL.validateSig(asset))
};
```

### Creating a SEAL

TODO

## Contributing

Contributions are welcome!

- [Create an issue](https://github.com/bgon/SEAL-js/issues)
- [Fork this repository](https://github.com/bgon/SEAL-js/fork)
- [Open a pull request](https://github.com/bgon/SEAL-js/pulls)

## License

Distributed under MIT License. See `LICENSE` and `LICENSE-typescript`for more information.

