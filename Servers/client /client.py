#Yam chernichovsky
from header import *
# Define the default server address and port
default_server_address = ('localhost', 1256) #server adress of authentication server
sucsess_codes_from_aserver= {CODE_REGISTRATION_SUCCESS,CODE_LIST_SERVERS,CODE_CLIENT_AS_SECRET_KEY_AND_TICKET}
my_info = {}
global m_server_names_and_uuid 
#all of those for m servers
server_id_iv = {}    #save the iv for the server        the server id is in string format iv is byte format
server_id_ip_port = {}    #save the ip and port for the server
server_id_aes_key = {}    #save the aes key for the server      the server id is byte format aes key is byte format

def get_m_server_uuid(server_name): #return the uuid of the server
    for uuid, name in m_server_names_and_uuid:
        if name == server_name:
            return uuid
    return None

def update_global_UUID(uuid_ascii): #update my uuid localy
    my_info['uuid_ascii'] = uuid_ascii
    my_info['uuid_bin'] = hex_ascii_to_bin(uuid_ascii)

def update_global_data(name,password,password_hash,uuid_ascii): #update my info localy
    my_info['username'] = name
    my_info['password'] = password
    my_info['password hash'] = password_hash    # Hash the password to string hexa
    my_info['uuid_ascii'] = uuid_ascii
    my_info['uuid_bin'] = hex_ascii_to_bin(uuid_ascii)

def save_to_me_info_file(uuid):     # save my info to me.info file
    try:   
       with open('me.info', 'w') as file:
            file.write(f"{default_server_address}\n")
            file.write(f"{my_info['username']}\n")
            file.write(f"{uuid}\n")
            file.write(f"{my_info['password']}\n")
            file.write(f"{my_info['password hash']}\n")
            return uuid
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")
 
def client_secret_key_and_ticket_handler(data,payload_size ,server_id): #help conection to new M server. get message from A server and return M server adress and buffer for M server
    ticket = ticket_struct.unpack(data[from_as_header_struct.size +encrypted_key_ipport_struct.size :from_as_header_struct.size+encrypted_key_ipport_struct.size+ticket_struct.size])
    enckrypted_key = encrypted_key_ipport_struct.unpack(data[from_as_header_struct.size:from_as_header_struct.size+encrypted_key_ipport_struct.size])
    iv = enckrypted_key[0]
    #print("\n\n iv recived from a server : ",iv,"\n\n")
    #print (f"iv : {iv}")
    aes_key_encrypted_by_client_key = enckrypted_key[1]
    server_ip = enckrypted_key[2]
    server_port = enckrypted_key[3]
    password_hash = hash_SHA256_ret_bytes(my_info['password'])    # Hash the password to string hexa
    #print(f"my_info['password'] : {my_info['password']}")
    #print(f"password_hash : {password_hash}")
    #password_hash = hashlib.sha256(my_info['password'].encode()).hexdigest()    # Hash the password
    #print(f"aes_key_encrypted_by_client_key : {aes_key_encrypted_by_client_key}")
    aes_key_for_comunication = decrypt_AES(aes_key_encrypted_by_client_key, password_hash, iv) # Decrypt the AES key
    aes_key_for_comunication = unpad_AES(aes_key_for_comunication)
    #print(f"aes_key_for_comunication : {aes_key_for_comunication}")
    #print(f"server_ip : {server_ip}")
    #print(f"server_port : {server_port}")
    server_address = (server_ip.decode(),int(server_port.decode()))
    server_id_aes_key[server_id] = aes_key_for_comunication


    #create budder for the message server
    #authenticator build from :  encrypred_version,encrypred_client_id,encrypred_server_id,encrypted_timestamp
    encrypred_version = encrypt_AES(VERSION.to_bytes(1, byteorder='big'), aes_key_for_comunication, iv)
    encrypted_client_id = encrypt_AES(my_info['uuid_bin'], aes_key_for_comunication, iv)
    encrypted_server_id = encrypt_AES(hex_ascii_to_bin(server_id), aes_key_for_comunication, iv)
    enctypred_timestamp = encrypt_AES(str(get_timestamp(0)).encode(), aes_key_for_comunication, iv)

    #print(f"encrypred_version size : {len(encrypred_version)}")
    #print(f"encrypted_client_id size : {len(encrypted_client_id)}")
    #print(f"encrypted_server_id size : {len(encrypted_server_id)}")
    #print(f"enctypred_timestamp size : {len(enctypred_timestamp)}")


    buffer = bytearray(to_server_header_struct.size+authenticator_struc.size+ticket_struct.size)
    to_server_header_struct.pack_into(buffer,0,my_info['uuid_bin'],VERSION,CODE_TO_M_SERVER_S_KEY,authenticator_struc.size+ticket_struct.size)
    authenticator_struc.pack_into(buffer,to_server_header_struct.size,encrypred_version,encrypted_client_id,encrypted_server_id,enctypred_timestamp)
    ticket_struct.pack_into(buffer,to_server_header_struct.size+authenticator_struc.size,ticket[0],ticket[1],ticket[2],ticket[3],ticket[4],ticket[5],ticket[6])

    return server_address,buffer
   
def recive_data_from_aserver_checker(data):  #check if M server answer. return 0 for eror, return 1 for sucsess
    #unpack service request data
    version, code, payload_size  = extruct_info_from_aserver_response(data)
    
    if version != VERSION:
        print("version error")
        return 0

    if code not in sucsess_codes_from_aserver:
        if code == CODE_REGISTRATION_FAILURE:
            print("registration failure")
        elif code == CODE_NETWORK_EROR:
            print("network error")
        else:
            print(f"Unknown code: {code}")
        return 0                                        

    return 1        
    
def extruct_info_from_aserver_response(data): #get data from A server and:  version, code, payload_size
    recived_data = from_as_header_struct.unpack(data[:from_as_header_struct.size])
    version = recived_data[0] 
    code = recived_data[1] 
    payload_size = recived_data[2]
    return version, code, payload_size

def send_data_to_server(server_address,buffer): #send buffer to server and return server answer
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
            # Connect to the server
            print(f"Connecting to {server_address}")
            client_socket.connect(server_address)
            client_socket.sendall(buffer)
            data = client_socket.recv(1024)
            return data
    except ConnectionRefusedError:
            print("The server refused the connection")
            return 0
    except ConnectionResetError:
            print("The server reset the connection")
            return 0
    except socket.error as e:
        print(f"Failed to send data to the server: {e}")
    finally:
            # Close the socket
            client_socket.close()
            print("Socket closed.")

def register(): #register to A server, use server adress from port.info file
        # Use the default server address and port
        #server_address = default_server_address                                 
        #added 12.3
        try:
            with open('port.info', 'r') as f:  # 'r' for read
                a_server_port = f.read() 
                a_server_port = int(a_server_port)      # Convert the port number to an integer##############12.3
                server_address = ('localhost', a_server_port)                                                                     
        except FileNotFoundError:
            print('port.info file not found, use defult port 1256')
            server_address = ('localhost', 1256)  
            a_server_port = 1256
        # Ask the user for their username and password and pack it into a struct
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        my_info['username'] = username
        my_info['password'] = password
        password_hash = hash_SHA256_ret_bytes(password)    # Hash the password to string hexa
        my_info['password hash'] = password_hash    # Hash the password to string hexa
        buffer = bytearray(to_server_header_struct.size+client_reg_payload_struct.size)
        to_server_header_struct.pack_into(buffer,0,username.encode(),VERSION,CODE_CLIENT_REGISTRATION,client_reg_payload_struct.size)
        client_reg_payload_struct.pack_into(buffer,to_server_header_struct.size,username.encode(),password.encode())
        serv_ans = send_data_to_server(server_address,buffer)
        if recive_data_from_aserver_checker(serv_ans) == 1:
            print("client registration success")
            uuid_bin = uuid_payload_struct.unpack(serv_ans[from_as_header_struct.size:from_as_header_struct.size+uuid_payload_struct.size])[0]
            update_global_data(username,password,password_hash,bin_to_hex_ascii(uuid_bin))
            #print(f"uuid : {bin_to_hex_ascii(uuid_bin)}")
            return save_to_me_info_file(bin_to_hex_ascii(uuid_bin))        #return uuid asci or exit    
        else:
            print("client registration fail")
            exit(1)

def get_sem_key_buffer_for_as(server_id):   #get buffer for A server to get secret key and ticket for M server
    iv = os.urandom(16) # Generate a random IV
    server_id_iv[server_id] = iv        #save the iv for the server                     
    buffer = bytearray(to_server_header_struct.size+client_server_key_exchange_payload_struct.size)
    to_server_header_struct.pack_into(buffer,0,my_info['uuid_bin'],VERSION,CODE_CLIENT_SERVER_KEY_EXCHANGE,client_server_key_exchange_payload_struct.size)
    client_server_key_exchange_payload_struct.pack_into(buffer,to_server_header_struct.size,my_info['uuid_bin'],hex_ascii_to_bin(server_id),iv)      #client_id,server_id,nonce
    return buffer

def get_mserver_list():    #get list of M servers, print and save it                  
    print("Connected to the server.")
    buffer = bytearray(to_server_header_struct.size)
    to_server_header_struct.pack_into(buffer,0,my_info['uuid_bin'],VERSION,CODE_GET_SERVER_LIST,0)
    server_ans = send_data_to_server(default_server_address,buffer)
    payload_size = from_as_header_struct.unpack(server_ans[:from_as_header_struct.size])[2]
    server_names_bin =  mServers_list_payload_struct.unpack(server_ans[from_as_header_struct.size: from_as_header_struct.size + mServers_list_payload_struct.size])[1] #.strip(b'\x00')
    server_names_bin_striped = server_names_bin[:payload_size]
    server_names = pickle.loads(server_names_bin_striped)
    global m_server_names_and_uuid
    m_server_names_and_uuid = server_names
    # Store only the server names in a list
    server_names_only = [name for uuid, name in server_names]
    # Print the server names
    print ("Server names: ")
    for name in server_names_only:
        print(name + " ") 
      
def talk_to_m_server(server_id):    #connect to new M server to do it, get secret key and ticket from A server
    buffer = get_sem_key_buffer_for_as(server_id)
    a_server_ans = send_data_to_server(default_server_address,buffer)
    #print(f" after requesting ticket a_server_ans : {a_server_ans}")
    payload_size = from_as_header_struct.unpack(a_server_ans[:from_as_header_struct.size])[2]
    server_adress, buffer = client_secret_key_and_ticket_handler(a_server_ans,payload_size,server_id) 
    server_id_ip_port[server_id] = server_adress
    m_server_ans = send_data_to_server(server_adress,buffer)
    if (int(m_server_ans.decode()) == CODE_FROM_M_SERVER_S_KEY_RECIVED):
        print("can talk to m server")
        return 1
    else:
        return 0

def talk_to_connected_m_server(server_id,message): #talk to connected mesage server and return the answer
    message = message.encode()
    if server_id in server_id_aes_key:
        encrypted_message = encrypt_AES(message, server_id_aes_key[server_id], server_id_iv[server_id])
        #print("\n\n iv actualy used for sending mesage to m server : ",server_id_iv[server_id],"\n\n")
    else:
        print(f"The key {server_id} does not exist in server_id_aes_key. ask for key from A server")
        return CODE_NETWORK_EROR
    #encrypted_message = encrypt_AES(message,server_id_aes_key[server_id],server_id_iv[server_id])
    message_size = len(encrypted_message)
    buffer = bytearray(to_server_header_struct.size+message_to_m_server_struct.size+message_size)
    to_server_header_struct.pack_into(buffer,0,my_info['uuid_bin'],VERSION,CODE_TO_M_SERVER_MAS_SEND,message_to_m_server_struct.size+message_size)
    message_to_m_server_struct.pack_into(buffer,to_server_header_struct.size,message_size,server_id_iv[server_id])
    buffer[to_server_header_struct.size+message_to_m_server_struct.size:to_server_header_struct.size+message_to_m_server_struct.size+message_size] = encrypted_message
    m_server_ans = send_data_to_server(server_id_ip_port[server_id],buffer)
    return m_server_ans

def init(): #main function if me.info file not exist, register to A server, else read from me.info file
    if not os.path.exists('me.info'):           # Check if the me.info file not exists
        # Register the client
        uuid_ascii = register()
    else:
         # Read the IP:Port and UUID from the file
        with open('me.info', 'r') as file:
            lines = file.readlines()
            name = lines[1].strip()
            uuid_ascii = lines[2].strip()
            password = lines[3].strip()
            password_hash = lines[4].strip()
            update_global_data(name,password,password_hash,uuid_ascii)
       
    while True:
            input_from_user = input("What you wont to do? \n [1] GET SERVER LIST \n [2] COMMUNICATE TO NEW MESSAGE SERVER \n [3] TALK TO CONNECTED M SERVER \n [4] EXIT \n")
            
            if input_from_user == '1':
                get_mserver_list()
               
            if input_from_user == '2':
                server_name = input("Enter server name or enter: exit for return to main menu \n")
                server_id = get_m_server_uuid(server_name)
                if server_id != 'exit':
                    if (talk_to_m_server(server_id)==1):
                        while True :
                            what_to_send =  input("What you wont to do? \n [1] SEND MESSAGE [2] EXIT \n")   
                            if what_to_send == '1':
                                message = input("Enter your message: ")
                                ans = talk_to_connected_m_server(server_id,message)
                                print(ans.decode())
                            if what_to_send == '2':
                                break

            if input_from_user == '3':
                print("talk to connected m server")
                server_name = input("Enter server name or enter: exit for return to main menu \n")
                server_id = get_m_server_uuid(server_name)
                if server_id != 'exit':
                    message = input("Enter your message: ")
                    talk_to_connected_m_server(server_id,message)
                    #server_address = get_server_ip_port(server_id)
                    #connect_to_server(server_address)
                    while True :
                        what_to_send =  input("What you wont to do? \n [1] SEND MESSAGE [2] EXIT \n")   
                        if what_to_send == '1':
                            message = input("Enter your message: ")
                     #       send_message(server_address,message)
                        if what_to_send == '2':
                            break
                    
            if input_from_user == '4':
                break


def main(): 
    init()

if __name__ == "__main__":
    main()  
