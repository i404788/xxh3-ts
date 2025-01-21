import xxhash
import subprocess
import secrets

# test_str = "WAIDHOAWDHOAWIDHAOWIDHIOAIWODHAOWIDHAOWIDHOAIWHDOAIHWDOIAWHDOIAHWDOIAHWDOIHAWODIHAWODIHAWODIHA"

for len in [2, 6, 12, 18, 32+18, 64, 96]:
    test_str = secrets.token_hex(len)

    local_xxh64_hash = xxhash.xxh64_intdigest(test_str.encode())
    local_xxh3_128_hash = xxhash.xxh3_128_intdigest(test_str.encode())

    ref_xxh3_128_hash = int(subprocess.check_output(["node", "-e", "const { XXH3_128 } = require('./xxh3.js'); console.log(XXH3_128(Buffer.from(\"%s\")).toString(10))" % test_str]).strip())
    ref_xxh64_hash = int(subprocess.check_output(["node", "-e", "const { XXH64 } = require('./xxh64.js'); console.log(XXH64(Buffer.from(\"%s\")).toString(10))" % test_str]).strip())

    xxh64_res = '✅' if local_xxh64_hash == ref_xxh64_hash else f"xxh64 not eq to ref, {local_xxh64_hash=} != {ref_xxh64_hash=}"
    print(f'[ALGO=XXH64, LEN={len}]: {xxh64_res}')

    xxh3_128_res = '✅' if local_xxh3_128_hash == ref_xxh3_128_hash else f"xxh3_128 not eq to ref, {local_xxh3_128_hash=} != {ref_xxh3_128_hash=}"
    print(f'[ALGO=XXH3_128, LEN={len}]: {xxh3_128_res}')
