
# Sending tesnet bitcoins using only the networking protocol

### You have been sent some unknown amount of testnet bitcoins to your address. 

Send all of it back (minus fees) to `mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv` using only the networking protocol.


```python
# Exercise 4.1

from merkleblock import MerkleBlock, MerkleTree

last_block_hex = '<fill this in>'
last_block = bytes.fromhex(last_block_hex)
passphrase = b'<fill this in>'  # FILL THIS IN
secret = little_endian_to_int(hash256(passphrase))
private_key = PrivateKey(secret=secret)
addr = private_key.point.address(testnet=True)
print(addr)
h160 = decode_base58(addr)
target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
filter_size = 30
filter_num_functions = 5
filter_tweak = -1  # FILL THIS IN
target_h160 = decode_base58(target_address)
target_script = p2pkh_script(target_h160)
fee = 5000  # fee in satoshis

# connect to tbtc.programmingblockchain.com in testnet mode, logging True
# create a bloom filter using variables above
# add the h160 to the bloom filter
# complete the handshake
# send the 'filterload' command with bf.filterload() as the payload

# create GetHeadersMessage with the last_block as the start_block
# send a getheaders message

# wait for the headers message
# get the stream from the headers
# parse the headers message

# initialize the GetDataMessage
# loop through the blocks in the headers message
    # check that the proof of work on the block is valid
    # check that this block's prev_block is the last block
    # set the last block to the current hash
    # add_data(FILTERED_BLOCK_DATA_TYPE, last_block) to get_data_message
# send the get_data_message

# initialize prev_tx to None
# while prev_tx is None 
    # wait for the merkleblock or tx commands
    # initialize the stream from the envelope
    # if we have the merkleblock command
        # parse the MerkleBlock
        # check that the MerkleBlock is valid
    # else we have the tx command
        # parse the tx (prev)
        # loop through the enumerated tx outs (enumerate(prev.tx_outs))
            # if our output has the same address as our address (addr) we found it
                # we found our utxo. set prev_tx, prev_index, prev_amount
                # break
# create tx_in
# calculate the output amount (prev_amount - fee)
# create tx_out
# create transaction on testnet
# sign the one input we have
# serialize and hex to see what it looks like
# send this signed transaction on the network
# wait a sec so this message goes through to the other node sleep(1) 
# now ask for this transaction from the other node
# create a GetDataMessage
# add_data (TX_DATA_TYPE, tx_obj.hash()) to get data message
# send the GetDataMessage
# now wait for a response
# if we have the tx command
    # parse the tx
    # check that the ids are the same
        # yes! we got to what we wanted
```
