const PRIME64_1 = 11400714785074694791n;
const PRIME64_2 = 14029467366897019727n;
const PRIME64_3 = 1609587929392839161n;
const PRIME64_4 = 9650029242287828579n;
const PRIME64_5 = 2870177450012600261n;
const mask64 = (1n << 64n) - 1n;

// Basically (byte*)buf + offset
function getView(buf: Buffer, offset: number = 0): Buffer {
    return Buffer.from(buf.buffer, buf.byteOffset + offset, buf.length - offset)
}

function Rotl64(a: bigint, n: bigint) {
    return (a << n) | (a >> (64n - n)) & mask64
}

function round(acc: bigint, lane: bigint) {
    acc = (acc + (lane * PRIME64_2)) & mask64;
    acc = Rotl64(acc, 31n) & mask64;
    return (acc * PRIME64_1) & mask64;
}

function XH64_mergeAccumulator(acc: bigint, accN: bigint) {
    acc = acc ^ round(0n, accN);
    acc = (acc * PRIME64_1) & mask64
    return (acc + PRIME64_4) & mask64;
}

function XH64_convergeAccumulator(accs: BigUint64Array): bigint {
    let acc = Rotl64(accs[0], 1n) + Rotl64(accs[1], 7n) + Rotl64(accs[2], 12n) + Rotl64(accs[3], 18n);
    acc = XH64_mergeAccumulator(acc, accs[0]);
    acc = XH64_mergeAccumulator(acc, accs[1]);
    acc = XH64_mergeAccumulator(acc, accs[2]);
    acc = XH64_mergeAccumulator(acc, accs[3]);
    return acc
}

function XH64_accumulateRemainder(data: Buffer, acc: bigint): bigint {
    let offset = 0
    while (data.byteLength - offset >= 8) {
        let lane = data.readBigUInt64LE(offset);
        acc = acc ^ round(0n, lane);
        acc = Rotl64(acc, 27n) * PRIME64_1;
        acc = (acc + PRIME64_4) & mask64;
        offset += 8;
    }

    if (data.byteLength - offset >= 4) {
        let lane = BigInt(data.readUInt32LE(offset));
        acc = (acc ^ (lane * PRIME64_1)) & mask64;
        acc = (Rotl64(acc, 23n) * PRIME64_2) & mask64;
        acc = (acc + PRIME64_3) & mask64;
        offset += 4;
    }

    while (data.byteLength - offset >= 1) {
        let lane = BigInt(data.readUInt8(offset));
        acc = (acc ^ (lane * PRIME64_5)) & mask64;
        acc = (Rotl64(acc, 11n) * PRIME64_1) & mask64;
        offset += 1;
    }
    return acc
}

function XH64_accumulate(data: Buffer, accs: BigUint64Array) {
    const fullStripes = Math.floor(data.byteLength / 32)
    for (let i = 0; i < fullStripes; i++) {
        for (let j = 0; j < 4; j++) {
            let lane = data.readBigUInt64LE(i * 32 + j * 8)
            accs[j] = round(accs[j], lane)
        }
    }

    let acc = XH64_convergeAccumulator(accs)
    acc += BigInt(data.byteLength)

    if (fullStripes != data.byteLength / 32) {
        acc = XH64_accumulateRemainder(getView(data, fullStripes * 32), acc)
    }

    return XH64_mix(acc)
}

function XH64_mix(acc: bigint) {
    acc = acc ^ (acc >> 33n);
    acc = (acc * PRIME64_2) & mask64;
    acc = acc ^ (acc >> 29n);
    acc = (acc * PRIME64_3) & mask64;
    acc = acc ^ (acc >> 32n);
    return acc
}

function XXH64_small(data: Buffer, seed: bigint) {
    let acc = (seed + PRIME64_5) & mask64;
    acc = XH64_accumulateRemainder(data, acc)
    return XH64_mix(acc)
}


export function XXH64(data: Buffer, seed: bigint = 0n) {
    if (data.byteLength < 32) return XXH64_small(data, seed)
    const acc = new BigUint64Array([
        seed + PRIME64_1 + PRIME64_2,
        seed + PRIME64_2,
        seed,
        seed - PRIME64_1
    ])

    return XH64_accumulate(data, acc)
}