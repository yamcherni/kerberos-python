import socket
import socket
import os
import struct
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import hashlib
import time
import binascii
import pickle
from datetime import datetime, timedelta
import ast
import sys




VERSION = 24
CODE_CLIENT_REGISTRATION = 1025
CODE_SERVER_REGISTRATION = 1026           #1027 in the pdf
CODE_CLIENT_SERVER_KEY_EXCHANGE = 1027   #1026 in the pdf
CODE_GET_SERVER_LIST = 1028             #1026 in the pdf
CODE_REGISTRATION_SUCCESS = 1600
CODE_REGISTRATION_FAILURE = 1601
CODE_LIST_SERVERS = 1602
CODE_CLIENT_AS_SECRET_KEY_AND_TICKET = 1603
CODE_TO_M_SERVER_S_KEY = 1028
CODE_TO_M_SERVER_MAS_SEND = 1029
CODE_NETWORK_EROR = 1609
CODE_FROM_M_SERVER_S_KEY_RECIVED = 1604
CODE_FROM_M_SERVER_MAS_RECIVED = 1605
keyLenBits = 256  # for AES-256
aes_key_len_bytes = int(keyLenBits / 8)
default_server_address = ('localhost', 1256)

#asrr = authentication server registration request
#use big endian

to_server_header_struct = struct.Struct('> 16s B H I')                          #header of message send to authentication server                            client ID,version,code,payload size
from_as_header_struct = struct.Struct('> B H I')                                #header of message send from authentication server                          version,code,payload size
server_reg_payload_struct = struct.Struct('> 255s 32s  9s I')     #cahnged 21.1             #struct send to authentication server for server registration               server ID,server password,ip,port
client_reg_payload_struct = struct.Struct('> 255s 255s')                        #struct send to authentication server for client registration               client ID,client password
client_server_key_exchange_payload_struct = struct.Struct('> 16s 16s 16s')        #struct send to authentication server for client server key exchange        client ID,server ID,nonce
uuid_payload_struct = struct.Struct('> 16s')                                     #struct send from when client/server registration success                   client/server ID
mServers_list_payload_struct = struct.Struct('> 16s 255s')                      #struct send from authentication server when client ask for server list     Server ID,Server Name
encrypted_key_ipport_struct = struct.Struct('> 16s 48s 9s 5s')                               #struct send from authentication server as part of symetric key (1603)      IV,AES_KEY
ticket_struct = struct.Struct('> B 16s 16s 17s 16s 48s 32s')  #time stamp padded to 16 bytes                        #struct send from authentication server as part of symetric key (1603)      version,client ID,server ID,timestamp,IV,AES_KEY,expiration time

encrypted_key_and_ticket_to_client_struct = struct.Struct('> 16s 48s 146s')            #struct send from authentication server as part of symetric key (1603)      IV,AES_KEY,version,client ID,server ID,timestamp,IV,AES_KEY,expiration time
authenticator_struc = struct.Struct('> 16s 32s 32s 32s')                            #struct send from clint to message server  as part of symetric key (1208)   version,client ID,server ID,timestamp                              
message_to_m_server_struct = struct.Struct('> I 16s')


def bin_to_hex_ascii(bin):
    return binascii.hexlify(bin).decode()

def hex_ascii_to_bin(hex_ascii):
    return binascii.unhexlify(hex_ascii)

def get_timestamp(offset):     #offset is the time in minutes
    now = datetime.now()  # Get the current time
    # Calculate the expiration time
    offset_time = now + timedelta(minutes=offset)  
    timestamp = offset_time.timestamp() # Get the timestamp
    return timestamp            #str(timestamp).encode()


def encrypt_AES(data, key , iv):
    key = key[:32].encode() if isinstance(key, str) else key[:32]
    iv = iv.encode() if isinstance(iv, str) else iv
    data = data.encode() if isinstance(data, str) else data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size)) 
    return encrypted_data
    

def decrypt_AES(data, key , iv):
    key = key[:32]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def unpad_AES(data):
    unpadded_data = unpad(data, AES.block_size)
    return unpadded_data


def hash_SHA256_ret_bytes(data):  # take string and Returns the hash as a string of hexadecimal digits
    data = data.encode()
    hash_object = hashlib.sha256(data)
    hash_bytes = hash_object.digest()
    return hash_bytes