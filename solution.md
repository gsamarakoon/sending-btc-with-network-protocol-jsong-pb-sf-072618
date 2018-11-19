
# Sending tesnet bitcoins using only the networking protocol

### You have been sent some unknown amount of testnet bitcoins to your address. 

Send all of it back (minus fees) to `mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv` using only the networking protocol.


```python
# Exercise 4.1

from time import sleep
from block import Block
from bloomfilter import (
    BloomFilter,
    BIP37_CONSTANT,
)
from ecc import PrivateKey
from helper import (
    bit_field_to_bytes,
    decode_base58,
    hash160,
    hash256,
    little_endian_to_int,
    murmur3,
    run,
    SIGHASH_ALL,
)
from merkleblock import MerkleBlock
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
    FILTERED_BLOCK_DATA_TYPE,
    TX_DATA_TYPE,
)
from tx import (
    Tx,
    TxIn,
    TxOut,
)
from script import p2pkh_script

# Exercise 4.1

from merkleblock import MerkleBlock, MerkleTree

last_block_hex = '000000000d65610b5af03d73ed67704713c9b734d87cf4b970d39a0416dd80f9'
last_block = bytes.fromhex(last_block_hex)
passphrase = b'Jimmy Song Programming Blockchain'  # FILL THIS IN
secret = little_endian_to_int(hash256(passphrase))
private_key = PrivateKey(secret=secret)
addr = private_key.point.address(testnet=True)
print(addr)
h160 = decode_base58(addr)
target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
filter_size = 30
filter_num_functions = 5
filter_tweak = 90210  # FILL THIS IN
target_h160 = decode_base58(target_address)
target_script = p2pkh_script(target_h160)
fee = 5000  # fee in satoshis

# connect to tbtc.programmingblockchain.com in testnet mode, logging True
node = SimpleNode('tbtc.programmingblockchain.com', testnet=True, logging=True)
# create a bloom filter using variables above
bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)
# add the h160 to the bloom filter
bf.add(h160)
# complete the handshake
node.handshake()
# send the 'filterload' command with bf.filterload() as the payload
node.send(b'filterload', bf.filterload())

# create GetHeadersMessage with the last_block as the start_block
getheaders_message = GetHeadersMessage(start_block=last_block)
# send a getheaders message
node.send(getheaders_message.command, getheaders_message.serialize())

# wait for the headers message
headers_envelope = node.wait_for_commands([HeadersMessage.command])
# get the stream from the headers
stream = headers_envelope.stream()
# parse the headers message
headers = HeadersMessage.parse(stream)

# initialize the GetDataMessage
get_data_message = GetDataMessage()
# loop through the blocks in the headers message
for block in headers.blocks:
    # check that the proof of work on the block is valid
    if not block.check_pow():
        raise RuntimeError
    # check that this block's prev_block is the last block
    if last_block is not None and block.prev_block != last_block:
        raise RuntimeError
    # set the last block to the current hash
    last_block = block.hash()
    # add_data(FILTERED_BLOCK_DATA_TYPE, last_block) to get_data_message
    get_data_message.add_data(FILTERED_BLOCK_DATA_TYPE, last_block)
# send the get_data_message
node.send(get_data_message.command, get_data_message.serialize())

# initialize prev_tx to None
prev_tx = None
# while prev_tx is None 
while prev_tx is None:
    # wait for the merkleblock or tx commands
    envelope = node.wait_for_commands([b'merkleblock', b'tx'])
    # initialize the stream from the envelope
    stream = envelope.stream()
    # if we have the merkleblock command
    if envelope.command == b'merkleblock':
        # parse the MerkleBlock
        mb = MerkleBlock.parse(stream)
        # check that the MerkleBlock is valid
        if not mb.is_valid():
            raise RuntimeError
    # else we have the tx command
    else:
        # parse the tx (prev)
        prev = Tx.parse(stream, testnet=True)
        # loop through the enumerated tx outs (enumerate(prev.tx_outs))
        for i, tx_out in enumerate(prev.tx_outs):
            # if our output has the same address as our address (addr) we found it
            if tx_out.script_pubkey.address(testnet=True) == addr:
                # we found our utxo. set prev_tx, prev_index, prev_amount
                prev_tx = prev.hash()
                prev_index = i
                prev_amount = tx_out.amount
                # break
                break
# create tx_in
tx_in = TxIn(prev_tx, prev_index)
# calculate the output amount (prev_amount - fee)
output_amount = prev_amount - fee
# create tx_out
tx_out = TxOut(output_amount, target_script)
# create transaction on testnet
tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)
# sign the one input we have
tx_obj.sign_input(0, private_key)
# serialize and hex to see what it looks like
print(tx_obj.serialize().hex())
# send this signed transaction on the network
node.send(b'tx', tx_obj.serialize())
# wait a sec so this message goes through to the other node sleep(1) 
sleep(1)
# now ask for this transaction from the other node
# create a GetDataMessage
getdata = GetDataMessage()
# add_data (TX_DATA_TYPE, tx_obj.hash()) to get data message
getdata.add_data(TX_DATA_TYPE, tx_obj.hash())
# send the GetDataMessage
node.send(getdata.command, getdata.serialize())
# now wait for a response
envelope = node.wait_for_commands([b'tx', b'reject'])
# if we have the tx command
if envelope.command == b'tx':
    # parse the tx
    got = Tx.parse(envelope.stream())
    # check that the ids are the same
    if got.id() == tx_obj.id():
        # yes! we got to what we wanted
        print('success!')
        print(tx_obj.id())
else:
    print(envelope.payload)
```
