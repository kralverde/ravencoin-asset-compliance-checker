import json
import requests
import threading
import time

from hashlib import sha256
from typing import Union

USERNAME = 'user'
PASSWORD = 'pass'
PORT = 18766 # 8766
KAWPOW_START = 231544 # 1219736
LOG = False
ERR = True

ASSET_START = 0 # 400_000
NUM_THREADS = 16

def debug_print(s: str):
    if LOG:
        print(s)

def log_print(s: str):
    if ERR:
        print(s)

class ByteReader:
    def __init__(self, b: bytes):
        self.pointer = 0
        self.data = b

    def _assert_can_read(self, count):
        if (avail := self.bytes_avaliable()) < count: raise Exception(f'Cannot read {count} bytes (only {avail} avaliable)')

    def bytes_avaliable(self) -> int:
        return max(0, len(self.data) - self.pointer)

    def read_uint8(self) -> int:
        return self.read_bytes(1)[0]
    
    def read_bytes(self, count) -> bytes:
        self._assert_can_read(count)
        _bytes = self.data[self.pointer:self.pointer+count]
        self.pointer += count
        return _bytes

def read_var_int(b: bytes):
    if b[0] < 0xFD:
        return 1, b[0]
    if b[0] == 0xFD:
        return 3, int.from_bytes(b[1:3], 'little', signed=False)
    if b[0] == 0xFE:
        return 5, int.from_bytes(b[1:5], 'little', signed=False)
    else:
        return 9, int.from_bytes(b[1:9], 'little', signed=False)


def dsha256(b):
    return sha256(sha256(b).digest()).digest()


def post_request(session: requests.Session, method: str, params):
    data = {
        'jsonrpc':'2.0',
        'id':'0',
        'method': method,
        'params': params
    }
    resp = session.post(f'http://{USERNAME}:{PASSWORD}@localhost:{PORT}', data=json.dumps(data))
    return resp.json()['result']


def get_ops(script):
    '''
    Returns a tuple list of (op_code, index of next op in script, pushed bytes if any)

    If at any point the script fails do decode, a tuple of (-1, len(script), remaining script) is appended
    '''
    ops = []

    # The unpacks or script[n]
    n = 0
    try:
        while n < len(script):
            op = script[n]
            op_v = (script[n], n+1)
            n += 1
            if op <= 0x4e:
                # Raw bytes follow
                if op < 0x4c:
                    dlen = op
                    n1 = 0
                elif op == 0x4c:
                    dlen = script[n]
                    n1 = 1
                elif op == 0x4d:
                    dlen = int.from_bytes(script[n: n + 2], 'little', signed=False)
                    n1 = 2
                else:
                    dlen = int.from_bytes(script[n: n + 4], 'little', signed=False)
                    n1 = 4
                if n + n1 + dlen > len(script):
                    raise IndexError
                n += n1
                op_v = (op, n+dlen, script[n:n + dlen])
                n += dlen

            ops.append(op_v)
    except (IndexError):
        # n - 1 because we read a byte first
        ops.append((-1, len(script), script[n-1:]))

    return ops


#   https://github.com/RavenProject/Ravencoin/blob/e48d932ec70267a62ec3541bdaf4fe022c149f0e/src/script/script.cpp#L245
def is_invalid_asset_vout(script: bytes) -> Union[bool, str]:
    if len(script) > 31:
        if script[25] == 0xc0:
            asset_start_index = -1
            if script[27:30] == b'rvn':
                asset_start_index = 30
            elif script[28:31] == b'rvn':
                asset_start_index = 31

            if asset_start_index >= 0:
                if script[asset_start_index] not in (b't'[0], b'q'[0], b'o'[0], b'r'[0]):
                    return False
                
                # At this point, the asset is valid according to the core
                asset_name_length = script[asset_start_index+1]
                asset_name_bytes = script[asset_start_index+2:asset_start_index+2+asset_name_length]

                script_ops = get_ops(script)
                # [(op, index of next op in script)|(push, length, data),...]
                if any(x[0] == -1 for x in script_ops):
                    # Invalid script
                    log_print('invalid script')
                    return asset_name_bytes.decode() or True
                
                if script_ops[-1][0] != 0x75:
                    # Doesn't end with an OP_DROP
                    log_print('invalid script')
                    return asset_name_bytes.decode() or True
                
                op_asset_pointer = -1
                for i, tup in enumerate(script_ops):
                    if tup[0] == 0xc0:
                        op_asset_pointer = i
                        break
                else:
                    # No OP_RVN_ASSET (should never happen)
                    log_print('no OP_ASSET')
                    return asset_name_bytes.decode() or True
                
                should_be_asset_data = script_ops[op_asset_pointer + 1]
                should_be_op_drop = script_ops[op_asset_pointer + 2]

                if should_be_op_drop[0] != 0x75:
                    # OP_DROP isn't after the asset data
                    log_print('no trailing OP_DROP')
                    return asset_name_bytes.decode() or True
                
                if should_be_asset_data[0] > 0x4e:
                    # What should be an OP_PUSH isnt
                    log_print('not OP_PUSH')
                    return asset_name_bytes.decode() or True
                
                asset_data = should_be_asset_data[2]

                try:
                    byte_reader = ByteReader(asset_data)
                    if byte_reader.read_bytes(3) != b'rvn':
                        log_print('not asset data')
                        return asset_name_bytes.decode() or True
                    script_type = byte_reader.read_uint8()
                    if script_type not in (b't'[0], b'q'[0], b'o'[0], b'r'[0]):
                        log_print('unknown vout type')
                        return asset_name_bytes.decode() or True
                    asset_name_length = byte_reader.read_uint8()
                    asset_name_bytes = byte_reader.read_bytes(asset_name_length)
                    if script_type != b'o'[0]:
                        # Not a ownership vout
                        # sats
                        byte_reader.read_bytes(8)
                        if script_type == b't'[0]:
                            # transfer asset: check for memo
                            if byte_reader.bytes_avaliable() >= 34:
                                # memo
                                byte_reader.read_bytes(34)
                                if byte_reader.bytes_avaliable() >= 8:
                                    # timestamp
                                    byte_reader.read_bytes(8)
                        elif script_type == b'q'[0]:
                            # asset creation
                            # divisions / reissuable
                            byte_reader.read_bytes(2)
                            has_ipfs = byte_reader.read_uint8()
                            if has_ipfs != 0:
                                # associated ipfs
                                ipfs = byte_reader.read_bytes(34)
                        elif script_type == b'r'[0]:
                            # asset reissue
                            # divisions / reissuable
                            byte_reader.read_bytes(2)
                            if byte_reader.bytes_avaliable() >= 34:
                                # ipfs change
                                byte_reader.read_bytes(34)

                    if byte_reader.bytes_avaliable() > 0:
                        # Extra data
                        log_print('extra data')
                        return asset_name_bytes.decode() or True

                except Exception as e:
                    log_print(f'parse fail {repr(e)}')
                    return asset_name_bytes.decode() or True
    return False

def check_chunk(session: requests.Session, start: int, end: int, bad_transaction_set, bad_asset_name_set):
    for local_height in range(start, end):
        try:
            block_hash = post_request(session, 'getblockhash', [local_height])
            block_hex = post_request(session, 'getblock', [block_hash, 0])

            b = bytes.fromhex(block_hex)
            
            #size = b[:4]
            #b = b[4:]
            #print(f'block size: {size.hex()} ({int.from_bytes(size, "big")})')
            
            v = b[:4]
            b = b[4:]

            # Header
            debug_print(f'version: {v.hex()} ({int.from_bytes(v, "little")})')
            prev_hash = b[:32]
            b = b[32:]
            debug_print(f'prevhash: {prev_hash.hex()} ({prev_hash[::-1].hex()})')
            merkle_root = b[:32]
            b = b[32:]
            debug_print(f'merkle root: {merkle_root.hex()} ({merkle_root[::-1].hex()})')
            ts = b[:4]
            b = b[4:]
            debug_print(f'timestamp: {ts.hex()} ({int.from_bytes(ts, "little")})')
            bits = b[:4]
            b = b[4:]
            debug_print(f'bits: {bits.hex()} ({int.from_bytes(bits, "little")})')
            if local_height < KAWPOW_START:
                nonce = b[:4]
                b = b[4:]
                debug_print(f'nonce: {nonce.hex()} ({int.from_bytes(nonce, "little")})')
            else:
                nheight = b[:4]
                b = b[4:]
                debug_print(f'nheight: {nheight.hex()} ({int.from_bytes(nheight, "little")})')
                nonce = b[:8]
                b = b[8:]
                debug_print(f'nonce: {nonce.hex()} ({int.from_bytes(nonce, "little")})')
                mix_hash = b[:32]
                b = b[32:]
                debug_print(f'mix hash: {mix_hash.hex()} ({mix_hash[::-1].hex()})')

            # Actual block
            cut, num_transactions = read_var_int(b)
            b = b[cut:]
            debug_print(f'number of tranasctions: {num_transactions}')
            
            for i in range(num_transactions):
                wit_flag = False
                v = b[:4]
                tx_b = v
                b = b[4:]
                debug_print(f'transaction {i} version: {v.hex()} ({int.from_bytes(v, "little")})')
                if b[0] == 0:
                    assert b[1] == 1
                    debug_print(f'transaction {i}: flag is present')
                    b = b[2:]
                    wit_flag = True

                cut, num_vins = read_var_int(b)
                tx_b += b[:cut]
                b = b[cut:]
                debug_print(f'transaction {i} vin count: {num_vins}')
                for j in range(num_vins):
                    prev_txid = b[:32]
                    tx_b += b[:32]
                    b = b[32:]
                    debug_print(f'transaction {i} vin {j} prev txid: {prev_txid.hex()} ({prev_txid[::-1].hex()})')
                    prev_idx = b[:4]
                    tx_b += b[:4]
                    b = b[4:]
                    debug_print(f'transaction {i} vin {j} prev idx: {prev_idx.hex()} ({int.from_bytes(prev_idx, "little")})')
                    cut, script_length = read_var_int(b)
                    tx_b += b[:cut]
                    b = b[cut:]
                    script = b[:script_length]
                    tx_b += b[:script_length]
                    b = b[script_length:]
                    debug_print(f'transaction {i} vin {j} script: {script.hex()}')
                    sequence = b[:4]
                    tx_b += b[:4]
                    b = b[4:]
                    debug_print(f'transaction {i} vin {j} sequence: {sequence.hex()} ({int.from_bytes(sequence, "little")})')

                cut, num_vouts = read_var_int(b)
                tx_b += b[:cut]
                b = b[cut:]

                tx_has_bad_asset_vout = False

                debug_print(f'transaction {i} vout count: {num_vouts}')
                for j in range(num_vouts):
                    value = b[:8]
                    tx_b += b[:8]
                    b = b[8:]
                    debug_print(f'transaction {i} vout {j} value: {value.hex()} ({int.from_bytes(value, "little")})')
                    cut, script_length = read_var_int(b)
                    tx_b += b[:cut]
                    b = b[cut:]
                    script = b[:script_length]                
                    tx_b += b[:script_length]
                    b = b[script_length:]
                    debug_print(f'transaction {i} vout {j} script: {script.hex()}')
                    result = is_invalid_asset_vout(script)
                    if not tx_has_bad_asset_vout:
                        tx_has_bad_asset_vout = bool(result)
                    if isinstance(result, str):
                        bad_asset_name_set.add(result)

                if wit_flag:
                    for j in range(num_vins):
                        cut, wit_for_in = read_var_int(b)
                        b = b[cut:]
                        debug_print(f'transaction {i} vin {j} has witness count {wit_for_in}')
                        for _ in range(wit_for_in):
                            cut, data_len = read_var_int(b)
                            b = b[cut:]
                            data = b[:data_len]
                            b = b[data_len:]
                            debug_print(f'transaction {i} vin {j} witness data: {data.hex()} (len: {data_len})')

                lock_time = b[:4]
                tx_b += b[:4]
                b = b[4:]
                debug_print(f'transaction {i} locktime: {lock_time.hex()} ({int.from_bytes(lock_time, "little")})')
                txid = dsha256(tx_b)[::-1].hex()
                debug_print(f'transaction {i} txid: {txid}')

                if tx_has_bad_asset_vout:
                    bad_transaction_set.add(txid)

        except Exception as e:
            print(f'failed at height {local_height} tx num {i}')


def main():
    session = requests.Session()

    data = post_request(session, 'getblockchaininfo', [])
    final_height = data['blocks']

    start_height = ASSET_START
    end_height = final_height

    count_per_thread = (end_height - start_height) // NUM_THREADS

    bad_assets = set()
    bad_txids = set()

    print(f'Finding assets from {start_height} to {start_height + NUM_THREADS * count_per_thread} over {NUM_THREADS} threads with {count_per_thread} blocks per thread')
    start_time = time.time()

    threads = []
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=lambda: check_chunk(session,
                                                             start_height+i*count_per_thread, 
                                                             start_height+(i+1)*count_per_thread, 
                                                             bad_txids, 
                                                             bad_assets))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end_time = time.time()

    print(f'Complete: {end_time-start_time:.2f}sec ({(end_time-start_time) / (end_height-start_height):.5f}sec per block)')

    with open('bad_assets.json', 'w') as f:
        json.dump(sorted(bad_assets), f, indent=2)

    with open('bad_txids.json', 'w') as f:
        json.dump(list(bad_txids), f, indent=2)


if __name__ == '__main__':
    main()
