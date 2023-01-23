# xxh3-ts
xxhash implementation in pure typescript (using tc39 bigint), supports XXH64 & XXH3-128.
These algorithms require Node.js >=12.x, because of `Buffer::readBigUInt64LE`

## Usage:
```ts
import { XXH64 } from 'xxh3-ts';
import { Buffer } from 'buffer';

let hash: bigint = XXH64(Buffer.from(JSON.stringify(v)))
```
For conversion back to buffer it's recommended to use [bigint-buffer](https://www.npmjs.com/package/bigint-buffer) package or the following snippet:
```ts
function toBufferBE(num: bigint): Buffer {
  const hex = num.toString(16);
  // Padding *is* needed otherwise the last nibble will be dropped in an edge case
  return Buffer.from(hex.padStart(Math.ceil(hex.length/2) * 2, '0'), 'hex');
}
```

## XXH64
XXH64 was derived from the specifications at https://github.com/Cyan4973/xxHash/blob/v0.7.0/doc/xxhash_spec.md

## XXH3-128
XXH3-128 was ported from https://github.com/Cyan4973/xxHash/blob/v0.7.0/xxh3.h

As there is no specificatino for XXH3 in the specification documents.