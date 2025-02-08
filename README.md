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

## Compatibility
XXH64 & XXH3-128 were derived from the [specifications](https://github.com/Cyan4973/xxHash/blob/v0.8.3/doc/xxhash_spec.md#xxh3-algorithm-overview) and is input/output compatible with [upstream v0.8.3](https://github.com/Cyan4973/xxHash/blob/v0.8.3)

