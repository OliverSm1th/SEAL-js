/**
 * The remote signer https://signmydata.com provides a suite of already-signed files
 * if you would like to test the verification process.
 * 
 * Download Link (Zip file, 62Mb): https://signmydata.com/?samples=test
 * 
*/
import path from 'path';
import { promises, readFileSync } from 'node:fs';
import { assert } from 'chai';

import { SEAL } from '../dist/seal.js';
import { MediaAsset } from '../dist/mediaasset.js'
//Directory of the test files
let filesDirectory = './tests/fixtures';

filesDirectory = path.resolve(filesDirectory)
let test_files: any[] = [];
let max_tests = 100;
await promises
  .readdir(filesDirectory)

  // If promise resolved and
  // data are fetched
  .then((filenames) => {
    for (let filename of filenames) {
      test_files.push(filesDirectory + '/' + filename);
    }
  })

  // If promise is rejected
  .catch((err) => {
    console.log(err);
  });

describe('Seal Validation Tests', () => {
  let i = 0;
  for (let test_file of test_files) {
    it(test_file + ' should return true', async () => {
      const buf = readFileSync(test_file);
      let asset = {
        data: buf,
        name: path.basename(test_file),
      }
      let result = await SEAL.validateSig(asset,false);
      assert.equal(result.valid, true);
    });
    i++;
    if (i >= max_tests) {
      break;
    }
  }
});
