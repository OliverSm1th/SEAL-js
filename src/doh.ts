/************************************************
 SEAL: implemented in Typescript
 Original C code Copyright (c) 2024 Hacker Factor, Dr. Neal Krawetz
 Ported to TypeScript by Bertrand Gondouin (c) 2024
 See LICENSE & LICENSE-typescript
 ************************************************/

export class DoH {
  /**
   * getDNSTXTRecords(): Given a hostname and a DoH provider, get TXT records from DNS.
   * Returns: TXT records.
   *
   * @static
   * @param {string} hostname
   * @param {string} [doh_api='https://mozilla.cloudflare-dns.com/dns-query']
   * @return {*}  {Promise<string[]>}
   * @memberof SEAL
   */
  public static async getDNSTXTRecords(
    hostname: string,
    doh_api: string = 'https://mozilla.cloudflare-dns.com/dns-query',
  ): Promise<string[]> {
    console.time('getDNS_' + doh_api);

    return new Promise(async (resolve, reject) => {
      // Initialize the fetch URL and public keys object
      let fetchUrl: string;

      // DoH API providers

      // cloudflare: 'https://cloudflare-dns.com/dns-query',
      // mozilla: 'https://mozilla.cloudflare-dns.com/dns-query',
      // google: 'https://dns.google/resolve',

      // Construct the fetch URL based on the selected DoH provider
      fetchUrl = `${doh_api}?name=${hostname}&type=TXT`;

      // Fetch the DNS record and process the response
      await fetch(fetchUrl, {
        method: 'GET',
        headers: {
          accept: 'application/dns-json',
        },
      })
        .then((response) => {
          if (response.ok) {
            return response.json();
          }
          throw new Error('Unexpected server response, code: ' + response.status);
        })
        .then((data) => {
          if (data.Answer) {
            // Initialize an array to store the TXT records
            let records: string[] = [];
            // Process each record in the response
            data.Answer.forEach((record: any) => {
              let keyObject: any = {};

              // Parse the record data field and store key-value pairs
              const keyElements = record.data
                .replace(/".{0,1}"/g, '')
                .replace(/"/g, '')
                .split(' ');
              keyElements.forEach((element: string) => {
                const keyValuePair = element.split('=');
                keyObject[keyValuePair[0]] = keyValuePair[1];
              });

              // Add the key object to the public keys array
              records.push(keyObject);
            });

            resolve(records);
          } else {
            throw new Error('No Answer field from DoH');
          }
        })
        .catch((error) => {
          reject(error);
        });

      // End timing and resolve the promise with the public keys
      console.timeEnd('getDNS_' + doh_api);
    });
  }
}
