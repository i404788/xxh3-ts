// if (!(globalThis as any).Buffer) {
//    (globalThis as any).Buffer = require('buffer/').Buffer;
// }

const n = (n: number | string) => BigInt(n)

const PRIME32_1 = n('0x9E3779B1');  // 0b10011110001101110111100110110001
const PRIME32_2 = n('0x85EBCA77');  // 0b10000101111010111100101001110111
const PRIME32_3 = n('0xC2B2AE3D');  // 0b11000010101100101010111000111101
const PRIME64_1 = n('0x9E3779B185EBCA87');  // 0b1001111000110111011110011011000110000101111010111100101010000111
const PRIME64_2 = n('0xC2B2AE3D27D4EB4F');  // 0b1100001010110010101011100011110100100111110101001110101101001111
const PRIME64_3 = n('0x165667B19E3779F9');  // 0b0001011001010110011001111011000110011110001101110111100111111001
const PRIME64_4 = n('0x85EBCA77C2B2AE63');  // 0b1000010111101011110010100111011111000010101100101010111001100011
const PRIME64_5 = n('0x27D4EB2F165667C5');  // 0b0010011111010100111010110010111100010110010101100110011111000101
const PRIME_MX1 = n('0x165667919E3779F9');  // 0b0001011001010110011001111001000110011110001101110111100111111001
const PRIME_MX2 = n('0x9FB21C651E98DF25');  // 0b1001111110110010000111000110010100011110100110001101111100100101


const kkey = Buffer.from('b8fe6c3923a44bbe7c01812cf721ad1cded46de9839097db7240a4a4b7b3671fcb79e64eccc0e578825ad07dccff7221b8084674f743248ee03590e6813a264c3c2852bb91c300cb88d0658b1b532ea371644897a20df94e3819ef46a9deacd8a8fa763fe39c343ff9dcbbc7c70b4f1d8a51e04bcdb45931c89f7ec9d9787364eac5ac8334d3ebc3c581a0fffa1363eb170ddd51b7f0da49d316552629d4689e2b16be587d47a1fc8ff8b8d17ad031ce45cb3a8f95160428afd7fbcabb4b407e', 'hex')
const mask128 = (n(1) << n(128)) - n(1);
const mask64 = (n(1) << n(64)) - n(1);
const mask32 = (n(1) << n(32)) - n(1);
const STRIPE_LEN = 64
const KEYSET_DEFAULT_SIZE = 48   /* minimum 32 */
const STRIPE_ELTS = (STRIPE_LEN / 4)
const ACC_NB = (STRIPE_LEN / 8)
const _U64 = 8;
const _U32 = 4;



// Basically (byte*)buf + offset
function getView(buf: Buffer, offset: number = 0): Buffer {
    return Buffer.from(buf.buffer, buf.byteOffset + offset, buf.length - offset)
}

const bswap64 = (a: bigint) => {
    const scratchbuf = Buffer.allocUnsafe(8);
    scratchbuf.writeBigUInt64LE(a)
    return scratchbuf.readBigUInt64BE()
}

const bswap32 = (a: bigint) => {
    a = (a & n(0x0000FFFF)) << n(16) | (a & n(0xFFFF0000)) >> n(16);
    a = (a & n(0x00FF00FF)) << n(8) | (a & n(0xFF00FF00)) >>  n(8);
    return a
}

const XXH_mult32to64 = (a: bigint, b: bigint) => ((a & mask32) * (b & mask32)) & mask64
const assert = (a: boolean) => { if (!a) throw new Error('Assert failed') }

function rotl64(a: bigint, b: bigint) {
    return ((a << b) | (a >> (n(64) - b))) & mask64
}

function rotl32(a: bigint, b: bigint) {
    return ((a << b) | (a >> (n(32) - b))) & mask32
}


function XXH3_accumulate_512(acc: BigUint64Array, data: Buffer, key: Buffer) {
    for (let i = 0; i < ACC_NB; i++) {
        const left = 2 * i;
        const right = 2 * i + 1;
        const dataLeft = n(data.readUInt32LE(left * 4));
        const dataRight = n(data.readUInt32LE(right * 4)); //XXH_readLE32(xdata + right);
        acc[i] += XXH_mult32to64(dataLeft + n(key.readUInt32LE(left * 4)), dataRight + n(key.readUInt32LE(right * 4)))
        acc[i] += dataLeft + (dataRight << n(32));
    }
}

function XXH3_accumulate(acc: BigUint64Array, data: Buffer, key: Buffer, nbStripes: number) {
    for (let n = 0, k = 0; n < nbStripes; n++) {
        XXH3_accumulate_512(acc, getView(data, n * STRIPE_LEN), getView(key, k));
        k += 2
    }
}

function XXH3_scrambleAcc(acc: BigUint64Array, key: Buffer) {
    for (let i = 0; i < ACC_NB; i++) {
        const left = 2 * i;
        const right = 2 * i + 1;
        acc[i] ^= acc[i] >> n(47);
        const p1 = XXH_mult32to64((acc[i] & n('0xFFFFFFFF')), n(key.readUInt32LE(left)));
        const p2 = XXH_mult32to64(acc[i] >> n(32), n(key.readUInt32LE(right)));
        acc[i] = p1 ^ p2;
    }
}

function XXH3_mix2Accs(acc: Buffer, key: Buffer) {
    return XXH3_mul128(acc.readBigUInt64LE(0) ^ key.readBigUInt64LE(0),
        acc.readBigUInt64LE(_U64) ^ key.readBigUInt64LE(_U64));
}

function XXH3_mergeAccs(acc: Buffer, key: Buffer, start: bigint) {
    let result64 = start;

    result64 += XXH3_mix2Accs(getView(acc, 0 * _U64), getView(key, 0 * _U32));
    result64 += XXH3_mix2Accs(getView(acc, 2 * _U64), getView(key, 4 * _U32));
    result64 += XXH3_mix2Accs(getView(acc, 4 * _U64), getView(key, 8 * _U32));
    result64 += XXH3_mix2Accs(getView(acc, 6 * _U64), getView(key, 16 * _U32));

    return XXH3_avalanche(result64);
}

const NB_KEYS = ((KEYSET_DEFAULT_SIZE - STRIPE_ELTS) / 2) | 0
function XXH3_hashLong(acc: BigUint64Array, data: Buffer) {
    const block_len = STRIPE_LEN * NB_KEYS;
    const nb_blocks = (data.length / block_len) | 0;

    // console.log( nb_blocks, block_len)
    for (let n = 0; n < nb_blocks; n++) {
        XXH3_accumulate(acc, getView(data, n * block_len), kkey, NB_KEYS);
        XXH3_scrambleAcc(acc, getView(kkey, 4 * (KEYSET_DEFAULT_SIZE - STRIPE_ELTS)))
    }

    assert(data.length > STRIPE_LEN);
    {
        const nbStripes = (data.length % block_len) / STRIPE_LEN | 0;
        assert(nbStripes < NB_KEYS);
        XXH3_accumulate(acc, getView(data, nb_blocks * block_len), kkey, nbStripes);

        /* last stripe */
        if (data.length & (STRIPE_LEN - 1)) {
            const p = getView(data, data.length - STRIPE_LEN);
            XXH3_accumulate_512(acc, p, getView(kkey, nbStripes * 2));
        }
    }

}

function XXH3_hashLong_128b(data: Buffer, seed: bigint) {
    const acc = new BigUint64Array([seed, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME64_5, -seed, n(0)]);
    const accbuf = Buffer.from(acc.buffer)
    assert(data.length > 128);

    XXH3_hashLong(acc, data);

    /* converge into final hash */
    assert(acc.length * 8 == 64);
    {
        const low64 = XXH3_mergeAccs(accbuf, kkey, n(data.length) * PRIME64_1);
        const high64 = XXH3_mergeAccs(accbuf, getView(kkey, 16), n(data.length + 1) * PRIME64_2);
        return (high64 << n(64)) | low64
    }
}


function XXH3_mul128(a: bigint, b: bigint) {
    const lll = (a * b) & mask128;
    return (lll + (lll >> n(64))) & mask64;
}

function XXH3_mix16B(data: Buffer, key: Buffer) {
    return XXH3_mix2Accs(data, key)
    // return XXH3_mul128(data.readBigUInt64LE(0) ^ key.readBigUInt64LE(0),
    //     data.readBigUInt64LE(8) ^ key.readBigUInt64LE(8));
}

function XXH3_avalanche(h64: bigint) {
    h64 ^= h64 >> n(37);
    h64 *= PRIME_MX1;
    h64 &= mask64;
    h64 ^= h64 >> n(32);
    return h64;
}

function XXH3_avalanche64(h64: bigint) {
    h64 ^= h64 >> n(33);
    h64 *= PRIME64_2;
    h64 &= mask64;
    h64 ^= h64 >> n(29);
    h64 *= PRIME64_3;
    h64 &= mask64;
    h64 ^= h64 >> n(32);
    return h64;
}



function XXH3_len_1to3_128b(data: Buffer, key32: Buffer, seed: bigint) {
    const len = data.byteLength
    assert(len > 0 && len <= 3);

    const combined = n(data.readUInt8(len-1)) | n(len << 8) | n(data.readUInt8(0) << 16) | n(data.readUInt8(len>>1) << 24);
    const blow = (n(key32.readUInt32LE(0)) ^ n(key32.readUInt32LE(4))) + seed;
    const low = (combined ^ blow) & mask64;
    const bhigh = (n(key32.readUInt32LE(8)) ^ n(key32.readUInt32LE(12))) - seed;
    const high = (rotl32(bswap32(combined), n(13)) ^ bhigh) & mask64;

    return ((XXH3_avalanche64(high) & mask64) << n(64)) | XXH3_avalanche64(low)
}


function xorshift64(b: bigint, shift: bigint) {
    return b ^ (b >> shift);
}

function XXH3_len_4to8_128b(data: Buffer, key32: Buffer, seed: bigint) {
    const len = data.byteLength
    assert(len >= 4 && len <= 8);
    {
        const l1 = data.readUInt32LE(0)
        const l2 = data.readUInt32LE(len - 4);
        const l64 = n(l1) | (n(l2)<<n(32));
        const bitflip = ((key32.readBigUInt64LE(16) ^ key32.readBigUInt64LE(24)) + seed) & mask64;
        const keyed = l64 ^ bitflip;
        let m128 = (keyed * (PRIME64_1 + (n(len) << n(2)))) & mask128;
        m128 += (m128 & mask64) << n(65);
        m128 &= mask128;
        m128 ^= m128 >> n(67);

        return xorshift64((xorshift64(m128 & mask64, n(35)) * PRIME_MX2) & mask64, n(28)) |  (XXH3_avalanche(m128 >> n(64)) << n(64))
    }
}


function XXH3_len_9to16_128b(data: Buffer, key64: Buffer, seed: bigint) {
    const len = data.byteLength
    const scratchbuf = Buffer.alloc(8);
    assert(len >= 9 && len <= 16);
    {
        const bitflipl = key64.readBigUInt64LE(32) ^ key64.readBigUInt64LE(40);
        const bitfliph = key64.readBigUInt64LE(48) ^ key64.readBigUInt64LE(56);
        const ll1 = data.readBigUInt64LE();
        let ll2 = data.readBigUInt64LE(len - 8);

        let m128 = (ll1 ^ ll2 ^ bitflipl) * PRIME64_1;

        const m128_l = (m128 & mask64) + (n(len-1) << n(54));
        m128 = (m128 & (mask128 ^ mask64)) | m128_l; // eqv. to adding only to lower 64b
        ll2 ^= bitfliph;
        
        m128 += (ll2 + (ll2 & mask32) * (PRIME32_2-n(1))) << n(64)
        m128 &= mask128;
        m128 ^= bswap64(m128 >> n(64));
        let h128 = (m128 & mask64) * PRIME64_2;
        h128 += ((m128 >> n(64)) * PRIME64_2) << n(64);
        h128 &= mask128;

        return XXH3_avalanche(h128 & mask64) | XXH3_avalanche(h128 >> n(64)) << n(64); 
    }
}


function XXH3_len_0to16_128b(data: Buffer, seed: bigint) {
    const len = data.byteLength;
    assert(len <= 16);
    if (len > 8) return XXH3_len_9to16_128b(data, kkey, seed);
    if (len >= 4) return XXH3_len_4to8_128b(data, kkey, seed);
    if (len > 0) return XXH3_len_1to3_128b(data, kkey, seed);
    return XXH3_avalanche64(seed ^ kkey.readBigUInt64LE(64) ^ kkey.readBigUInt64LE(72)) | (XXH3_avalanche64(seed ^ kkey.readBigUInt64LE(80) ^ kkey.readBigUInt64LE(88)) << n(64));
}

// 16 byte min input
export function XXH3_128(data: Buffer, seed: bigint = n(0)) {
    const len = data.byteLength
    if (len <= 16) return XXH3_len_0to16_128b(data, seed);

    let acc1 = PRIME64_1 * (n(len) + seed)
    let acc2 = n(0)
    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                if (len > 128) {
                    return XXH3_hashLong_128b(data, seed);
                }
                acc1 += XXH3_mix16B(getView(data, 48), getView(kkey, 96));
                acc2 += XXH3_mix16B(getView(data, len - 64), getView(kkey, 112));
            }
            acc1 += XXH3_mix16B(getView(data, 32), getView(kkey, 64));
            acc2 += XXH3_mix16B(getView(data, len - 48), getView(kkey, 80));
        }
        acc1 += XXH3_mix16B(getView(data, 16), getView(kkey, 32));
        acc2 += XXH3_mix16B(getView(data, len - 32), getView(kkey, 48));
    }
    acc1 += XXH3_mix16B(getView(data, 0), getView(kkey, 0));
    acc2 += XXH3_mix16B(getView(data, len - 16), getView(kkey, 16));

    const part1 = (acc1 + acc2) & mask64
    const part2 = ((acc1 * PRIME64_3) + (acc2 * PRIME64_4) + ((n(len) - seed) * PRIME64_2)) & mask64;

    return (XXH3_avalanche(part1) << n(64)) | mask64-XXH3_avalanche(part2)
}
