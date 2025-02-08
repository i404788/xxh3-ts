import xxhash
import subprocess
import secrets

# test_str = "WAIDHOAWDHOAWIDHAOWIDHIOAIWODHAOWIDHAOWIDHOAIWHDOAIHWDOIAWHDOIAHWDOIAHWDOIHAWODIHAWODIHAWODIHA"

for len in [0, 1, 2, 3, 6, 12, 18, 32+18, 64, 96, 128, 96*2, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]:
    test_str = secrets.token_hex(len)[:len]

    local_xxh64_hash = xxhash.xxh64_intdigest(test_str.encode())
    local_xxh3_128_hash = xxhash.xxh3_128_intdigest(test_str.encode())

    xxh3_node_script = "const { XXH3_128 } = require('./xxh3.js'); console.log(XXH3_128(Buffer.from(\"%s\")).toString(10))" % test_str
    ref_xxh3_128_hash = int(subprocess.check_output(["node", "-e", xxh3_node_script]).strip())
    ref_xxh64_hash = int(subprocess.check_output(["node", "-e", "const { XXH64 } = require('./xxh64.js'); console.log(XXH64(Buffer.from(\"%s\")).toString(10))" % test_str]).strip())

    xxh64_res = '✅' if local_xxh64_hash == ref_xxh64_hash else f"xxh64 not eq to ref, \t{local_xxh64_hash=} !=\n \t\t\t{ref_xxh64_hash=}"
    print(f'[ALGO=XXH64, LEN={len}]: {xxh64_res}')

    xxh3_128_res = '✅' if local_xxh3_128_hash == ref_xxh3_128_hash else f"xxh3_128 not eq to ref, {local_xxh3_128_hash=:x} !=\n \t\t\t\t\t\t    {ref_xxh3_128_hash=:x}"
    print(f'[ALGO=XXH3_128, LEN={len}]: {xxh3_128_res}')
