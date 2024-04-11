#Yam chernichovsk
import socket
import socket
import os
import struct
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import time
import binascii
import pickle
from datetime import datetime, timedelta
import ast
from Crypto.Util.Padding import unpad




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
default_server_address = ('localhost', 1256)

#asrr = authentication server registration request


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


def bin_to_hex_ascii(bin):      # Convert the bytes to a hexadecimal string
    return binascii.hexlify(bin).decode()

def hex_ascii_to_bin(hex_ascii):    # Convert the hexadecimal string to bytes
    return binascii.unhexlify(hex_ascii)

def get_timestamp(offset):     #offset is the time in minutes
    now = datetime.now()  # Get the current time
    # Calculate the expiration time
    offset_time = now + timedelta(minutes=offset)  
    timestamp = offset_time.timestamp() # Get the timestamp
    return timestamp            #str(timestamp).encode()


def encrypt_AES(data, key , iv): #return encrypted data
    #print("encrypt_AES")
    #print('data: ',data)
    #print('key: ',key)
    #print('iv: ',iv)
    key = key[:32].encode() if isinstance(key, str) else key[:32]
    iv = iv.encode() if isinstance(iv, str) else iv
    data = data.encode() if isinstance(data, str) else data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size)) 
    return encrypted_data
    

def decrypt_AES(data, key , iv): #return decrypted data
    #print("decrypt_AES")
    #print('data: ',data)
    #print('key: ',key)
    #print('iv: ',iv)
    key = key[:32]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def unpad_AES(data):        #return unpadded data
    unpadded_data = unpad(data, AES.block_size)
    return unpadded_data



############################### header ########################################
global MY_NAME 
global MY_AES_KEY
global MY_ADDRESS
global MY_UUID
my_data= {}
clients ={}


def save_reg_date(my_adress,my_name,my_uuid,my_aes_key): # Write the data to the msg.info file
    try:   
        with open('msg.info', 'w') as file:
            file.write(f"{my_adress}\n")
            file.write(f"{my_name}\n")
            file.write(f"{my_uuid}\n")
            file.write(f"{my_aes_key}\n") #save in binary
            return 1
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")
        return 0

def update_global_data(my_adress,my_name,my_uuid,my_aes_key): #update global data
    global MY_NAME 
    global MY_AES_KEY
    global MY_ADDRESS
    global MY_UUID
    my_data['my_adress'] = my_adress
    my_data['my_name'] = my_name
    my_data['my_uuid'] = my_uuid
    my_data['my_aes_key'] = my_aes_key
    MY_ADDRESS = my_adress
    MY_NAME  = my_name
    MY_AES_KEY = my_aes_key
    MY_UUID = my_uuid

def extruct_info_from_aserver_response(data): #get version, code, payload_size
    recived_data = from_as_header_struct.unpack(data[:from_as_header_struct.size])
    version = recived_data[0] 
    code = recived_data[1] 
    payload_size = recived_data[2]
    return version, code, payload_size

def recive_data_from_aserver_checker(data):  #check the recived data. return 0 for eror, return 1 for sucsess
    #unpack service request data
    version, code, payload_size  = extruct_info_from_aserver_response(data)
    
    if version != VERSION:
        print("version error")
        return 0
    if code == CODE_REGISTRATION_SUCCESS:
        print("registration success")
        return 1
    if code == CODE_REGISTRATION_FAILURE:
        print("registration failure")
        return
    elif code == CODE_NETWORK_EROR:
        print("network error")
        return 0
    else:
        print(f"Unknown code: {code}")
    return 0                                        
    
def register(a_server_adress):     #registed to authentication server, takes the server adress. return my adress if sucsessd and 0 if not eror
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(a_server_adress)
        my_ip, my_port = server_socket.getsockname()    #ip-string port-int
        my_address = (my_ip, my_port)
        name = "m1Server"                   #this m server name
        aes_key = secrets.token_bytes(keyLenBits // 8) # Generate 32 random bytes for the AES key
        #print("/n #############################")
        #print("aes_key: ", aes_key)
        #print("/n #############################")
        #create registration request buffer
        buffer = bytearray(to_server_header_struct.size+server_reg_payload_struct.size)
        to_server_header_struct.pack_into(buffer,0,name.encode(),VERSION,CODE_SERVER_REGISTRATION,server_reg_payload_struct.size)
        server_reg_payload_struct.pack_into(buffer,to_server_header_struct.size,name.encode(),aes_key,my_ip.encode(),my_port)
        #send registration request to authentication server
        server_socket.sendall(buffer)
        serv_ans = server_socket.recv(1024)
        #check registration response
    finally:
        server_socket.close()
        print("Socket closed.")
    if recive_data_from_aserver_checker(serv_ans) == 1:
        #get uuid from the server response
        uuid = uuid_payload_struct.unpack(serv_ans[from_as_header_struct.size:from_as_header_struct.size+uuid_payload_struct.size])[0]
        uuid = bin_to_hex_ascii(uuid)             # Convert the bytes to a hexadecimal string that use as server uuid
        print(f"my uuid : {uuid}")
        if save_reg_date(my_address,name,uuid,aes_key) == 1:    #save the data to msg.info file
            update_global_data(my_address,name,uuid,aes_key)
            print("msg.info file updated")
            return my_address
        else:
            print("msg.info file not updated")
            return 0
    else:
        return 0

def save_clinet_data(client_id,client_aes_key,client_iv):   # update client file .1 for sucsess 0 for eror
    # Append the client data to the clients file
    client_id = bin_to_hex_ascii(client_id)
    client_aes_key = bin_to_hex_ascii(client_aes_key)
    client_iv = bin_to_hex_ascii(client_iv)
    try:
        with open('m1ServerClients', 'a') as clientsFile:  # 'a' for append
            clientsFile.write(f"{client_id}:{client_aes_key}:{client_iv}\n")
    except FileNotFoundError:
        print('clients file not found')
        return 0
    return 1

def load_clients():  #load clients data to the clients file
    try:
        with open('m1ServerClients', 'r') as clientsFile:  # 'r' for read
            for line in clientsFile:
                client_id, client_aes_key, client_iv = line.split(':')
                client_id = hex_ascii_to_bin(client_id) # Convert the hexadecimal string to bytes
                client_aes_key = hex_ascii_to_bin(client_aes_key) # Convert the hexadecimal string to bytes
                client_iv = ''.join(client_iv.split())  # Remove any whitespace
                client_iv = hex_ascii_to_bin(client_iv) # Convert the hexadecimal string to bytes
                clients[client_id] = (client_aes_key, client_iv)
    except FileNotFoundError:
        print('clients file not found')
        return 0
    return 1

def init(): #init the server, return my adress if sucsessd and 0 if not eror
     # Load the port number from port.info file or use default port 5050
    try:
        with open('port.info', 'r') as f:  # 'r' for read
            a_server_port = f.read() 
            a_server_port = int(a_server_port)      # Convert the port number to an integer##############12.3
            a_server_adress = ('localhost', a_server_port)                                                                     
    except FileNotFoundError:
        print('port.info file not found, use defult port 1256')
        a_server_adress = ('localhost', 1256)  
        a_server_port = 1256

    #a_server_adress = ('localhost', 1256)  #removed###################################12.3
    if not os.path.exists('msg.info'):           # Check if the msg.info file not exists. if not neet to register else already registered and need to restore the data
        # Register in authemtication server as mesage server client
        return(register(a_server_adress)) #will return my adress or 0 for eror
    else:
        try:
            with open('msg.info', 'r') as file:
                my_address = file.readline().strip()
                my_address = ast.literal_eval(my_address)   #stored as tuple
                my_name = file.readline().strip()
                my_uuid = file.readline().strip()
                my_aes_key = file.readline().strip()     # read as string
                #print("/n #############################")
                #print("my_aes_key: ", my_aes_key)
                #print("/n #############################")
               # print("File read successfully")
               # print(f"my_address: {my_address}")
               # print(f"my_name: {my_name}")
               # print(f"my_uuid: {my_uuid}")
               # print(f"my_aes_key: {my_aes_key}")
                update_global_data(my_address,my_name,my_uuid,my_aes_key)
                return my_address
        except IOError as e:
            print(f"An error occurred while reading the file: {e}")
            return 0

def new_client_conection_handler(data): #check if the the new client have valid ticket and add it to the clients list if he does
    authenticatoer = authenticator_struc.unpack(data[to_server_header_struct.size:to_server_header_struct.size+authenticator_struc.size])
    authenticator_version = authenticatoer[0]
    authenticator_client_id = authenticatoer[1]
    authenticator_server_id = authenticatoer[2]
    authenticator_timestamp = authenticatoer[3]
    ticket = ticket_struct.unpack(data[to_server_header_struct.size+authenticator_struc.size:to_server_header_struct.size+authenticator_struc.size+ticket_struct.size])
    ticket_version = ticket[0]
    ticket_client_id = ticket[1]
    ticket_server_id = bin_to_hex_ascii(ticket[2])
    ticket_timestamp = ticket[3]    #not in use
    ticket_iv = ticket[4]
    ticket_aes_key = ticket[5]
    ticket_expiration_time = ticket[6]
    #decrypt ticket
    MY_AES_KEY = my_data['my_aes_key']  ##there is a diference between the global and the local, need to make local on registation identical to stored in the file
    #print("MY_AES_KEY")
    print (MY_AES_KEY)
    try:
        MY_AES_KEY = ast.literal_eval(MY_AES_KEY)
    except (ValueError, SyntaxError):
        MY_AES_KEY = MY_AES_KEY
    print (MY_AES_KEY)
    decrypted_ticket_aes_key = decrypt_AES(ticket_aes_key, MY_AES_KEY, ticket_iv)
    decrypted_ticket_aes_key = unpad_AES(decrypted_ticket_aes_key)
    #print("decrypted_ticket_aes_key: ", decrypted_ticket_aes_key)
    #print(" decryped experation time :" , decrypt_AES(ticket_expiration_time, MY_AES_KEY, ticket_iv))
    #decrypted_ticket_expiration_time = decrypt_AES(ticket_expiration_time, MY_AES_KEY, ticket_iv)
    decrypted_ticket_expiration_time = unpad_AES(decrypt_AES(ticket_expiration_time, MY_AES_KEY, ticket_iv))  ##privious revsion 12.3
    #print("/n decrypted_ticket_expiration_time: ", decrypted_ticket_expiration_time)
    #decrypt authenticator
    decrypted_authenticator_version = decrypt_AES(authenticator_version, decrypted_ticket_aes_key, ticket_iv)
    decrypted_authenticator_client_id = unpad_AES(decrypt_AES(authenticator_client_id, decrypted_ticket_aes_key, ticket_iv))
    decrypted_authenticator_server_id = decrypt_AES(authenticator_server_id, decrypted_ticket_aes_key, ticket_iv)
    decrypted_authenticator_timestamp = unpad_AES(decrypt_AES(authenticator_timestamp, decrypted_ticket_aes_key, ticket_iv))
    #check ticket
    if ticket_version != VERSION:   #check version
        print("version error")
        return CODE_NETWORK_EROR
    #print(f"ticket_client_id: {ticket_client_id}")
    #print(f"decrypted_authenticator_client_id: {decrypted_authenticator_client_id}")
    if ticket_client_id != decrypted_authenticator_client_id:   #check client id
         print("client id error")
         return CODE_NETWORK_EROR
    #print(f"ticket_server_id: {ticket_server_id}")
    #print(f"decrypted_authenticator_server_id: {MY_UUID}")
    if ticket_server_id != MY_UUID:  #check server id
        print("server id error")
        return CODE_NETWORK_EROR
    if (float(decrypted_ticket_expiration_time.decode()) - float(decrypted_authenticator_timestamp.decode())) < 0:
        print("ticket expired")
        return CODE_NETWORK_EROR
    else:
        clients[decrypted_authenticator_client_id] = (decrypted_ticket_aes_key,ticket_iv)
        save_clinet_data(decrypted_authenticator_client_id,decrypted_ticket_aes_key,ticket_iv)
        print("client added to clients list")
        return CODE_FROM_M_SERVER_S_KEY_RECIVED    
    
def msg_from_existing_client(data,client_id):   #handle data from existing client add try except
    message_recived = message_to_m_server_struct.unpack(data[to_server_header_struct.size:to_server_header_struct.size+message_to_m_server_struct.size])
    message_size = message_recived[0]
    iv = message_recived[1]
    encrypted_message = struct.unpack(f'> {message_size}s',data[to_server_header_struct.size+message_to_m_server_struct.size:to_server_header_struct.size+message_to_m_server_struct.size+message_size])[0]
    decrypted_message = decrypt_AES(encrypted_message, clients[client_id][0], iv)
    #print(f"decrypted_message: {decrypted_message}")
    print(f"message from client {client_id} : {decrypted_message.decode()}")
    return CODE_FROM_M_SERVER_MAS_RECIVED

def data_from_client_handler(data): #check if the mesage is from a new client or from an existing client and send it to the hendler
    recived_data = to_server_header_struct.unpack(data[:to_server_header_struct.size])
    clint_id = recived_data[0] # 0 is the index of the client id in the struct
    version = recived_data[1] # 1 is the index of the version in the struct
    code= recived_data[2] # 2 is the index of the code in the struct
    payload_size = recived_data[3] # 3 is the index of the payload size in the struct
    if version != VERSION:
        return CODE_NETWORK_EROR
    if code == CODE_TO_M_SERVER_S_KEY:
        return(new_client_conection_handler(data))
    elif code == CODE_TO_M_SERVER_MAS_SEND:
        if clint_id in clients:
           return(msg_from_existing_client(data,clint_id))
    else:
        return CODE_NETWORK_EROR
    
def start_server(my_address): #start the server and lissen to the clients
    load_clients()
    HOST = my_address[0]
    PORT = my_address[1]
    
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the specified address and port
    server_socket.bind((HOST, int(PORT)))
    server_socket.listen(1)
    print(f"Server lissening on {HOST}:{PORT}")

    # Listen for incoming connections
    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address[0]}:{client_address[1]}")
        # Receive data from the client
        data = client_socket.recv(1024)
        print("Received data:")
        print(data)
        print("############################################# \n\n")
        ans = data_from_client_handler(data)
        ans = str(ans)
        client_socket.sendall(ans.encode())
        # Close the client connection
        client_socket.close()

  
def main():
    my_address = init()
    if my_address != 0:
        start_server(my_address)

if __name__ == "__main__":
    main()


#### i am updating me.info with nothing and then try to use it again
#### store data in hexa text
