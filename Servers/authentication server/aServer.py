#yam chernichovsky
from header import *
import threading

lock = threading.Lock()
clients = {}        # Dictionary of clients data
servers = {}        # Dictionary of M servers data

def get_server_info(server_id): #get M server id and return M server ip, server port, server aes key
    server = servers.get(server_id)
    if server:
        return server['ip'], server['port'], server['aes_key']
    return None, None

def get_client_info(client_id): #get client id and return client password hash, client last seen
    client = clients.get(client_id)
    if client:
        return client['password_hash'], client['last_seen']
    return None, None, None

def init(): #load this server port from port.info file, load clients and servers data from clients and servers files, return port number
    # Load the port number from port.info file or use default port 1256
    try:
        with open('port.info', 'r') as ports:  # 'r' for read
            port = int(ports.read())
    except FileNotFoundError:
        print('port.info file not found')
        port = 1256
    print(port)  # for debugging
    # Load clients data from clients file
    load_clients()
    # Load servers data from servers file
    load_servers()
    return port

def save_client_data(client_id, username, password_hash, timestamp): #save client data to clients file, return 1 if sucsess 0 if fail
     # Store the client data in the clients dictionary
    clients[client_id] = {
        'name': username,
        'password_hash': password_hash,
        'last_seen': timestamp
    }
    
    # Append the client data to the clients file
    try:
        with open('clients', 'a') as clientsFile:  # 'a' for append
            clientsFile.write(f"{client_id}:{username}:{password_hash}:{timestamp}\n")
    except FileNotFoundError:
        print('clients file not found')
        return 0
    print(f"User {username} registered successfully, client id : {client_id}")
    return 1

def client_registration_handler(data, payload_size):    # Handle client registration
    payload_data = client_reg_payload_struct.unpack(data[to_server_header_struct.size:to_server_header_struct.size+payload_size])
    username =  payload_data[0].decode().strip('\x00')               # 0 is the index of the user name in the struct
    password = payload_data[1].decode().strip('\x00')               # 1 is the index of the user password in the struct
    # Check if the username already exists
    for client in clients.values():
        if client['name'] == username:
            print(f"User {username} already exists")
            return CODE_REGISTRATION_FAILURE, 0                # Exit the function with failure code
        
    #password_hash = hashlib.sha256(password).hexdigest()    # Hash the password
    password_hash = hash_SHA256_ret_bytes(password)   # Hash the password - string hexa representation
    timestamp = time.time()                                 # Get the current timestamp
    random_bytes = secrets.token_bytes(16)                  # Generate 16 random bytes
    client_id = binascii.hexlify(random_bytes).decode()    # Convert the bytes to a hexadecimal string that use as client uuid
    buffer = bytearray(from_as_header_struct.size+len(random_bytes))
    if (save_client_data(client_id, username, password_hash, timestamp) == 1):  #1 sucsess 0 fail
        from_as_header_struct.pack_into(buffer,0,VERSION,CODE_REGISTRATION_SUCCESS,len(random_bytes)) #pack the header
        uuid_payload_struct.pack_into(buffer,from_as_header_struct.size,random_bytes)                   #pack the uuid
    else: buffer = reg_failier_buffer()
    return buffer

def load_servers():     # Load servers data from servers file
    try:
        with open('servers', 'r') as serversFile:
            for line in serversFile:
                server_data = line.strip().split(':')
                server_id = server_data[0]
                server_name = server_data[1]
                server_aes_key = server_data[2]
                server_ip = server_data[3]
                server_port = server_data[4]
                servers[server_id] = {
                    'name': server_name,
                    'aes_key':ast.literal_eval(server_aes_key),       #convert to original byte object
                    'ip': server_ip,
                    'port': server_port
                }

    except FileNotFoundError:
        print('servers file not found')

def load_clients():     # Load clients data from clients file
    try:
        with open('clients', 'r') as clientsFile:
            for line in clientsFile:
                client_data = line.strip().split(':')
                client_id = client_data[0]
                client_name = client_data[1]
                client_password_hash = ast.literal_eval(client_data[2]) #convert to bytes
                client_last_seen = client_data[3]
                clients[client_id] = {
                    'name': client_name,
                    'password_hash': client_password_hash,
                    'last_seen': client_last_seen
                }
    except FileNotFoundError:
        print('clients file not found')

def save_server_data(server_id, server_name, server_aes_key,server_ip,server_port): #save server data localy and to servers file, return 1 if sucsess 0 if fail
    #Store the server data in the servers dictionary
    servers[server_id] = {
        'name': server_name,
        'aes_key': server_aes_key,
        'ip': server_ip,
        'port': server_port
    }
    # Append the server data to the servers file
    try:
        with open('servers', 'a') as serversFile:                     # 'a' for append
            serversFile.write(f"{server_id}:{server_name}:{server_aes_key}:{server_ip}:{server_port}\n")
    except FileNotFoundError:
        print('servers file not found')
        return 0
    return 1                                        #1 sucsess 0 fail

def reg_failier_buffer(): #return registration failier buffer
        return from_as_header_struct.pack(VERSION,CODE_REGISTRATION_FAILURE,0)

def network_eror_buffer(): #return network eror buffer
        return from_as_header_struct.pack(VERSION,CODE_NETWORK_EROR,0)

def server_registration_handler(data,payload_size): # Handle server registration
    payload_data = server_reg_payload_struct.unpack(data[to_server_header_struct.size:to_server_header_struct.size+payload_size])
    server_name = payload_data[0].decode().strip('\x00')               # 0 is the index of the server name in the struct             
    server_aes_key = payload_data[1]                                  # 1 is the index of the aes key in the struct
    server_ip = payload_data[2].decode().strip('\x00')                # 2 is the index of the server ip in the struct
    server_port = str(payload_data[3])                                     # 3 is the index of the server port in the struct

    #print(f"server name {server_name}" )
    #print(f"aes key  {server_aes_key}")
    #print(f"server ip {server_ip}")
    #print(f"server port {server_port}")
    
     # Check if the server name already exists
    for server in servers.values():
         if server['name'] == server_name:
            print(f"Server {server_name} already exists")
            return reg_failier_buffer()
                     
    random_bytes = secrets.token_bytes(16)                          # Generate 16 random bytes
    server_id = binascii.hexlify(random_bytes).decode()             # Convert the bytes to a hexadecimal string that use as server uuid
    buffer = bytearray(from_as_header_struct.size+len(server_id))

    #print(f"random bytes : {random_bytes}")
    #print(f"server id : {server_id}")
    
    if (save_server_data(server_id, server_name, server_aes_key,server_ip,server_port) == 1):  #1 sucsess 0 fail
        from_as_header_struct.pack_into(buffer,0,VERSION,CODE_REGISTRATION_SUCCESS,len(random_bytes)) #pack the header
        uuid_payload_struct.pack_into(buffer,from_as_header_struct.size,random_bytes)                   #pack the uuid

    else :
        buffer = reg_failier_buffer()
    #print(f"random bytes len: {len(random_bytes)} ")            #for debugging
    #print(f"buffer : {buffer}")
    #print (f"unpacked uuid : {uuid_payload_struct.unpack(buffer[from_as_header_struct.size:from_as_header_struct.size+len(random_bytes)])[0]}")
    return buffer                    
    
def client_server_key_exchange_handler(data,payload_size): # Handle client-server key exchange
    payload_data = client_server_key_exchange_payload_struct.unpack(data[to_server_header_struct.size:to_server_header_struct.size+payload_size])
    client_id_bin = payload_data[0]                                     # 0 is the index of the client id in the struct
    server_id_bin = payload_data[1]                                     # 1 is the index of the server id in the struct
    client_id_ascii = bin_to_hex_ascii(payload_data[0])                                     # 0 is the index of the client id in the struct
    server_id_ascii = bin_to_hex_ascii(payload_data[1])                                    # 1 is the index of the server id in the struct
    iv = payload_data[2]                                                            # 2 is the index of the nonce in the struct, stay binary
    

    server_ip, server_port, server_aes_key = get_server_info(server_id_ascii)
    client_password_hash, client_last_seen = get_client_info(client_id_ascii)
    key_for_client_mserver_comunication = secrets.token_bytes(keyLenBits // 8)          #Generate a 256-bit key
    
    #print("key_for_client_mserver_comunication encryption for client ")
    encrypted_by_client_key_aes_key = encrypt_AES(key_for_client_mserver_comunication,client_password_hash,iv) #encrypt the symetric key with the server aes key
    #print("server_aes_key encryption for ticket")
    encrypted_by_server_aes_key_aes_key = encrypt_AES(key_for_client_mserver_comunication,server_aes_key,iv)
    encrypted_experation_time = encrypt_AES(str(get_timestamp(10)).encode(),server_aes_key,iv)                    #encrypt the expiration time with the symetric key, 10 minuts
    
    buffer = bytearray(from_as_header_struct.size + encrypted_key_ipport_struct.size + ticket_struct.size) 

    #pack the header
    from_as_header_struct.pack_into(buffer,0,VERSION,CODE_CLIENT_AS_SECRET_KEY_AND_TICKET,encrypted_key_ipport_struct.size + ticket_struct.size) #pack the header
    #pack the key
    #print ("encrypted_key_ipport_struct size should be")

    encrypted_key_ipport_struct.pack_into(buffer,from_as_header_struct.size,iv,encrypted_by_client_key_aes_key,server_ip.encode(),server_port.encode()) #pack the key
    #print ("encrypted_key_ipport_struct size is " ,encrypted_key_ipport_struct.size)
    #print(f" server_ip is {server_ip} , server_port is {server_port}")
    #print(f" it include iv size {len(iv)} , encrypted_by_client_key_aes_key size {len(encrypted_by_client_key_aes_key)} , server_ip size {len(server_ip.encode())}, server_port size {len(server_port.encode())}")
    #print (f" it len should be {len(iv)+ len(encrypted_by_client_key_aes_key) + len(server_ip.encode()) + len(server_port.encode())}")

    #pack the ticket
    ticket_struct.pack_into(buffer,from_as_header_struct.size + encrypted_key_ipport_struct.size ,VERSION,client_id_bin,server_id_bin,str(get_timestamp(0)).encode(),iv,encrypted_by_server_aes_key_aes_key,encrypted_experation_time) #create ticket binary
    #print (f"ticket_struct size is " ,ticket_struct.size)
    #print(f" it include version size {sys.getsizeof(VERSION)} , client_id_bin size {len(client_id_bin)} , server_id_bin size {len(server_id_bin)}, timestamp size {len(str(get_timestamp(0)).encode())}, iv size {len(iv)}, encrypted_by_server_aes_key_aes_key size {len(encrypted_by_server_aes_key_aes_key)}, encrypted_experation_time size {len(encrypted_experation_time)}")
    #print (f" it len should be {sys.getsizeof(VERSION) + len(client_id_bin) + len(server_id_bin) + len(str(get_timestamp(0)).encode()) + len(iv) + len(encrypted_by_server_aes_key_aes_key) + len(encrypted_experation_time)}")
    

    return buffer

def get_server_list_handler(data,payload_size): # Handle get server list
    recived_data = to_server_header_struct.unpack(data[:to_server_header_struct.size])
    client_id = recived_data[0]
    server_info = [(uuid, servers[uuid]['name']) for uuid in servers]  # Get a list of tuples (server_uuid, server_name)
    buffer = bytearray(from_as_header_struct.size+mServers_list_payload_struct.size)
    if len(server_info) > 255:
        server_info = server_info[:255]
    print(f"Sending server info: {server_info}")  # Print the server info for debugging
    server_info_bin = pickle.dumps(server_info)
    from_as_header_struct.pack_into(buffer,0,VERSION,CODE_LIST_SERVERS,len(server_info_bin)+16)  #16 is server id size
    mServers_list_payload_struct.pack_into(buffer,from_as_header_struct.size, client_id,server_info_bin)
    print(f"buffer : {buffer}")
    return buffer

# Dictionary of code handlers
code_handlers = {
    CODE_CLIENT_REGISTRATION: client_registration_handler,
    CODE_SERVER_REGISTRATION: server_registration_handler,
    CODE_CLIENT_SERVER_KEY_EXCHANGE: client_server_key_exchange_handler,
    CODE_GET_SERVER_LIST: get_server_list_handler
    
}

def recive_data_hendler(data):  #check the code and send the data to the right hendler
    #unpack service request data
    recived_data = to_server_header_struct.unpack(data[:to_server_header_struct.size])
    clint_id = recived_data[0] # 0 is the index of the client id in the struct
    version = recived_data[1] # 1 is the index of the version in the struct
    code= recived_data[2] # 2 is the index of the code in the struct
    payload_size = recived_data[3] # 3 is the index of the payload size in the struct

    if version != VERSION:
        return network_eror_buffer()
        exit(1)

    handler = code_handlers.get(code)     # Get the corresponding function for the code
    if handler is not None:
        buffer = handler(data,payload_size) 
    else:
        print(f"Unknown code: {code}")
        buffer = network_eror_buffer()
    return buffer

def handle_client(client_socket):
    data = client_socket.recv(1024)
    print("Received data:") 
    lock.acquire()
    send_data = recive_data_hendler(data)
    print(f" \n\n  Send data: {send_data} \n\n")            #buffer object
    client_socket.sendall(send_data) #recive data hendler and send answer to client
    lock.release()
    # Close the client connection
    client_socket.close()



def startServer(port):  #start server, listen to port, recive data, send it to recive data hendler, send the answer to the client
    # Define the server's IP address and port
    HOST = 'localhost'
    PORT = port

    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the specified address and port
    server_socket.bind((HOST, PORT))

    # Listen for incoming connections
    server_socket.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

        # Receive data from the client
        #data = client_socket.recv(1024)
        #print("Received data:") 
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
        #send_data = recive_data_hendler(data)
        #print(f" \n\n  Send data: {send_data} \n\n")            #buffer object
        #client_socket.sendall(send_data) #recive data hendler and send answer to client

        # Close the client connection
        #client_socket.close()

def main():
    port = init()
    startServer(port)

if __name__ == "__main__":
    main()
