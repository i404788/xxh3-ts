import xxhash
import subprocess
import secrets

# test_str = "WAIDHOAWDHOAWIDHAOWIDHIOAIWODHAOWIDHAOWIDHOAIWHDOAIHWDOIAWHDOIAHWDOIAHWDOIHAWODIHAWODIHAWODIHA"

node_script = """
const { XXH64, XXH3_128 } = require('./index.js');
const [data, seed] = process.argv.slice(1);
const buf = Buffer.from(data, 'hex');
console.log(XXH64(buf, BigInt(seed)).toString(10), XXH3_128(buf, BigInt(seed)).toString(10));
"""

inputs = []
for size in [0, 1, 2, 3, 4, 6, 8, 9, 12, 16, 18, 32+18, 64, 96, 128, 96*2, 240, 241, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]:
    # Raw bytes, not only hex digits: the 1-3 byte path shifts the middle byte
    # by 24 bits, so a value >= 0x80 there matters.
    test_bytes = bytearray(secrets.token_bytes(size))
    if size:
        test_bytes[size >> 1] |= 0x80
    inputs.append(bytes(test_bytes))
# 9-16 bytes: the low 64 bits of the product overflow when (len - 1) << 54 is added
inputs.append(bytes.fromhex('ad57c678563f342e48659322'))

failed = 0
for test_bytes in inputs:
    for seed in [0, 1, 0x9e3779b1, 2**63 + 12345]:
        local_xxh64_hash = xxhash.xxh64_intdigest(test_bytes, seed)
        local_xxh3_128_hash = xxhash.xxh3_128_intdigest(test_bytes, seed)

        out = subprocess.check_output(["node", "-e", node_script, test_bytes.hex(), str(seed)]).split()
        ref_xxh64_hash, ref_xxh3_128_hash = int(out[0]), int(out[1])

        xxh64_res = '✅' if local_xxh64_hash == ref_xxh64_hash else f"xxh64 not eq to ref, \t{local_xxh64_hash=} !=\n \t\t\t{ref_xxh64_hash=}"
        print(f'[ALGO=XXH64, LEN={len(test_bytes)}, SEED={seed}]: {xxh64_res}')

        xxh3_128_res = '✅' if local_xxh3_128_hash == ref_xxh3_128_hash else f"xxh3_128 not eq to ref, {local_xxh3_128_hash=:x} !=\n \t\t\t\t\t\t    {ref_xxh3_128_hash=:x}"
        print(f'[ALGO=XXH3_128, LEN={len(test_bytes)}, SEED={seed}]: {xxh3_128_res}')

        failed += (local_xxh64_hash != ref_xxh64_hash) + (local_xxh3_128_hash != ref_xxh3_128_hash)

exit(1 if failed else 0)
