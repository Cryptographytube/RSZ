import sys
import hashlib
from urllib.request import urlopen
import json
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import number_to_string, string_to_number
import base58

# ==============================================================================

def get_block_hash(block_height):
    try:
        htmlfile = urlopen(f"https://blockchain.info/block-height/{block_height}?format=json", timeout=20)
    except:
        print('Unable to connect to the internet to fetch block hash. Exiting..')
        sys.exit(1)
    block_data = json.loads(htmlfile.read().decode('utf-8'))
    return block_data['blocks'][0]['hash']

def get_txids_from_block(block_hash):
    try:
        htmlfile = urlopen(f"https://blockchain.info/block/{block_hash}?format=json", timeout=20)
    except:
        print('Unable to connect to the internet to fetch block data. Exiting..')
        sys.exit(1)
    block_data = json.loads(htmlfile.read().decode('utf-8'))
    return [tx['hash'] for tx in block_data['tx']]

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=20)
    except:
        print('Unable to connect to the internet to fetch RawTx. Exiting..')
        sys.exit(1)
    return htmlfile.read().decode('utf-8')

def get_rs(sig):
    try:
        rlen = int(sig[2:4], 16)
        r = sig[4:4 + rlen * 2]
        s = sig[8 + rlen * 2:]
        return r, s
    except Exception as e:
        print(f"Error in get_rs: {e}")
        return None, None

def split_sig_pieces(script):
    try:
        sigLen = int(script[2:4], 16)
        sig = script[2 + 2:2 + sigLen * 2]
        r, s = get_rs(sig[4:])
        if r is None or s is None:
            return None, None, None
        pubLen = int(script[4 + sigLen * 2:4 + sigLen * 2 + 2], 16)
        pub = script[4 + sigLen * 2 + 2:]
        return r, s, pub
    except Exception as e:
        print(f"Error in split_sig_pieces: {e}")
        return None, None, None

def parseTx(txn):
    try:
        inp_nu = int(txn[8:10], 16)
        if inp_nu != 2:
            return None  # Skip transactions that don't have exactly two inputs

        cur = 10
        inp_list = []
        for _ in range(inp_nu):
            prv_out = txn[cur:cur + 64]
            var0 = txn[cur + 64:cur + 64 + 8]
            cur = cur + 64 + 8
            scriptLen = int(txn[cur:cur + 2], 16)
            script = txn[cur:2 + cur + 2 * scriptLen]
            r, s, pub = split_sig_pieces(script)
            if r is None or s is None or pub is None:
                return None  # Skip transactions with invalid signature pieces
            seq = txn[2 + cur + 2 * scriptLen:10 + cur + 2 * scriptLen]
            inp_list.append([prv_out, var0, r, s, pub, seq])
            cur = 10 + cur + 2 * scriptLen
        rest = txn[cur:]
        return [txn[:10], inp_list, rest]
    except Exception as e:
        print(f"Error in parseTx: {e}")
        return None

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    for one in range(len(inp_list)):
        e = first
        for i in range(len(inp_list)):
            e += inp_list[i][0]  # prev_txid
            e += inp_list[i][1]  # var0
            if one == i:
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5]  # seq
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res

def HASH160(pubk_hex):
    return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubk_hex)).digest()).hexdigest()

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def calculate_private_key(r, s1, s2, z1, z2, p):
    return (z1 * s2 - z2 * s1) * modinv(r * (s1 - s2), p) % p

def private_key_to_address(private_key, compressed=True):
    sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    if compressed:
        pubkey = b'\x02' + number_to_string(vk.pubkey.point.x(), SECP256k1.order) if vk.pubkey.point.y() % 2 == 0 else b'\x03' + number_to_string(vk.pubkey.point.x(), SECP256k1.order)
    else:
        pubkey = b'\x04' + number_to_string(vk.pubkey.point.x(), SECP256k1.order) + number_to_string(vk.pubkey.point.y(), SECP256k1.order)

    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    address_prefix = b'\x00'
    address_payload = address_prefix + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(address_payload).digest()).digest()[:4]
    address = address_payload + checksum
    return base58.b58encode(address).decode('utf-8')

def check_balance(address):
    try:
        url = f"https://blockchain.info/rawaddr/{address}"
        response = urlopen(url, timeout=20)
        data = json.loads(response.read().decode('utf-8'))
        return data['final_balance'], data['total_received']
    except Exception as e:
        print(f"Unable to fetch balance for {address}: {e}")
        return 0, 0

def save_to_file(txid, private_key, address, balance, total_received):
    with open("winning_addresses.txt", "a") as f:
        f.write(f"TXID: {txid}\n")
        f.write(f"Private Key: {hex(private_key)}\n")
        f.write(f"Address: {address}\n")
        f.write(f"Balance: {balance}\n")
        f.write(f"Total Received: {total_received}\n")
        f.write("=" * 50 + "\n")

def main():
    block_height = int(input("Enter block number: "))
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    win_count = 0

    while True:
        try:
            block_hash = get_block_hash(block_height)
            txids = get_txids_from_block(block_hash)
            
            if not txids:
                print(f'No transactions found in block {block_height}')
                sys.exit(1)
            
            print(f'Found {len(txids)} transactions in block {block_height}')
            
            for txid in txids:
                try:
                    rawtx = get_rawtx_from_blockchain(txid)
                    parsed = parseTx(rawtx)
                    
                    if parsed is None:
                        continue  # Skip invalid transactions

                    e = getSignableTxn(parsed)
                    
                    r1, s1, z1 = int(e[0][0], 16), int(e[0][1], 16), int(e[0][2], 16)
                    r2, s2, z2 = int(e[1][0], 16), int(e[1][1], 16), int(e[1][2], 16)
                    
                    if r1 == r2:
                        private_key = calculate_private_key(r1, s1, s2, z1, z2, p)
                        print(f'Found matching r values for txid {txid}')
                        print(f'Private Key: {hex(private_key)}')

                        # Check for both compressed and uncompressed addresses
                        compressed_address = private_key_to_address(private_key, compressed=True)
                        uncompressed_address = private_key_to_address(private_key, compressed=False)

                        compressed_balance, compressed_total_received = check_balance(compressed_address)
                        uncompressed_balance, uncompressed_total_received = check_balance(uncompressed_address)

                        if compressed_balance > 0 or compressed_total_received > 0:
                            print(f"Compressed Address: {compressed_address} has balance: {compressed_balance}, total received: {compressed_total_received}")
                            save_to_file(txid, private_key, compressed_address, compressed_balance, compressed_total_received)
                            win_count += 1

                        if uncompressed_balance > 0 or uncompressed_total_received > 0:
                            print(f"Uncompressed Address: {uncompressed_address} has balance: {uncompressed_balance}, total received: {uncompressed_total_received}")
                            save_to_file(txid, private_key, uncompressed_address, uncompressed_balance, uncompressed_total_received)
                            win_count += 1
                except Exception as e:
                    print(f"Error processing txid {txid}: {e}")
                    continue  # Skip to the next transaction
            
            block_height += 1  # Move to the next block after processing all transactions in the current block
        except Exception as e:
            print(f"Error processing block {block_height}: {e}")
            continue  # Skip to the next block

    if win_count > 0:
        print(f"Found {win_count} winning addresses.")
    else:
        print("No winning addresses found.")

if __name__ == "__main__":
    main()