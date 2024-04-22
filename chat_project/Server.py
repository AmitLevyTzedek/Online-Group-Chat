import socket
import threading
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


host = '127.0.0.1'
port = 55555
Format = 'utf-8'
ADDR = (host, port)

IP = socket.gethostbyname(socket.gethostname())
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("[STARTING] server is starting....")
server_socket.bind(ADDR)
server_socket.listen()

# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'


class Client:
    def __init__(self, nickname, password, group):
        self.nickname = nickname
        self.password = password
        self.group = group


clients = []  # list for connected clients_socket
nicknames = []  # list for connected user's nicknames
passwords = []  # list for connected user's passwords
groups = []  # list for active groups
users = []  # list for connected users
number_of_admins = 3


# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()  # Removed encode() here
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode(Format)


# this function gets a message and a group_name and broadcast the message to all the users in group_name
def broadcast(message, group_name):
    for i in range(len(users)):
        if users[i].group == group_name:
            clients[i].send(encrypt(message.encode(Format)))


# this function gets a user and check if this user is an admin
def isAdmin(user):
    print("check4")
    try:
        with open("user_storage.txt", 'r') as file:
            # Read the first lines (the admins are in the first lines of the file)
            for i in range(number_of_admins):
                line = file.readline()
                # check if user is an admin
                if user.nickname in line and user.password in line:
                    return True
                return False
    except FileNotFoundError:
        return True
    return False


# handle function
def handle(client):
    while True:
        try:
            enc_message = client.recv(1024)
            msg = message = decrypt(enc_message)
            index = clients.index(client)
            print(msg)
            if isAdmin(users[index]):  # check if user is an admin
                if msg.startswith("KICK"):  # if the message is to kick a user
                    name_to_kick = msg[5:]
                    check = kick_user(name_to_kick, client)
                    if check is not None:
                        index_to_kick = nicknames.index(name_to_kick)
                        users[index_to_kick] = check
                    continue
                elif msg.startswith("SWC"):  # if the message is to switch room
                    switch_room(msg, client)
                elif msg.startswith("PASSWORD"):  # if the message is to switch password
                    change_password(client, msg)
                elif msg.startswith("CON_USERS"):  # if the message is to print all the connected users
                    show_connected_users(client)
                elif msg.startswith("FILE"):  # if the message is to send file
                    send_file(msg, client)
                else:  # regular message
                    group_name = users[index].group
                    write_data(message[len(users[index].nickname) + 1:], group_name, client)
                    broadcast(f'{msg}', group_name)
            else:  # the user is not an admin
                if msg.startswith("SWC"):  # if the message is to switch room
                    switch_room(msg, client)
                elif msg.startswith("PASSWORD"):  # if the message is to switch password
                    change_password(client, msg)
                elif msg.startswith("CON_USERS"):  # if the message is to print all the connected users
                    show_connected_users(client)
                elif msg.startswith("FILE"):  # if the message is to send file
                    send_file(msg, client)
                else:  # regular message
                    group_name = users[index].group
                    write_data(message[len(users[index].nickname) + 1:], group_name, client)
                    broadcast(message, group_name)

            nicknames[index] = users[index].nickname
        except ConnectionResetError:
            # Handle the connection reset error gracefully
            index = clients.index(client)
            name = nicknames[index]
            nicknames.remove(name)
            password = passwords[index]
            passwords.remove(password)
            group_name = groups[index]
            user = users[index]
            users.remove(user)
            clients.remove(client)
            client.close()
            broadcast(f'{name} left the chat', user.group)  # broadcast to the group that the user left
            print(f'{name} left the chat')  # Add this line to also print the message to the server console
            break
        except ValueError:
            print("Client not found in the list")
            break
        except Exception as e:
            print("An error occurred:", str(e))
            break


# receive function
def receive():
    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            print("Connected with ", str(client_addr))

            client_socket.send(encrypt("Enter nickname:".encode(Format)))  # enter nickname
            nickname = client_socket.recv(1024)
            nickname = decrypt(nickname)
            while nickname in nicknames:
                client_socket.send(encrypt("There is other user with this name, enter other nickname:".encode(Format)))
                nickname = client_socket.recv(1024)
                nickname = decrypt(nickname)

            client_socket.send(encrypt("Enter password:".encode(Format)))  # enter password
            password = client_socket.recv(1024)
            password = decrypt(password)
            while find_user_in_users(nickname, password) == 1:  # if a user with this name already exist
                client_socket.send(encrypt("There is other user with this name, enter other nickname:".encode(Format)))
                nickname = client_socket.recv(1024)
                nickname = decrypt(nickname)
                client_socket.send(encrypt("Enter password:".encode(Format)))
                password = client_socket.recv(1024)
                password = decrypt(password)

            client_socket.send(encrypt("Enter Group name:".encode(Format)))  # gets the room name
            group_name = client_socket.recv(1024)
            group_name = decrypt(group_name)
            groups.append(group_name)  # add the name to the list

            nicknames.append(nickname)  # add the nickname to the list

            passwords.append(password)  # add the password to the list

            user = Client(nickname, password, group_name)  # create a user with these details
            write_user_data(user)  # Save user data to file
            users.append(user)  # add user to the list
            clients.append(client_socket)

            print(f"nickname of client is {nickname}")
            # Add a delay before sending the "connected to the server" message
            time.sleep(1)
            # broadcast to users in the group the the user join the chat
            broadcast(f"{nickname} join the chat: {user.group}", user.group)

            thread = threading.Thread(target=handle, args=(client_socket,))
            thread.start()
        except ConnectionResetError:
            # Handle the connection reset error gracefully
            print("someone try to connect but left")
        except Exception as e:
            print("An error occurred in connection:", str(e))


# send name_to_kick to the kick room
def kick_user(name_to_kick, client):
    global users, nicknames
    flag = True
    if name_to_kick in nicknames:
        flag = False
        index_to_kick = nicknames.index(name_to_kick)
        client_to_kick = clients[index_to_kick]

        prv_group = users[index_to_kick].group
        new_group = "kick room"  # change the room of name_to_kick to kick room
        users[index_to_kick].group = new_group

        # Broadcast message after kicking the user
        broadcast(f"{name_to_kick} was kicked by an admin", prv_group)
        if users[clients.index(client)].group != prv_group:
            client.send(encrypt(f"{name_to_kick} was kicked by an admin".encode(Format)))

        write_server_to_data(f"{name_to_kick} was kicked by an admin",
                           prv_group)  # write to the data file that the message name_to_kick was kicked by an admin sent

        # Broadcast the user joining the kick room
        client_to_kick.send(encrypt("You were kicked from the group by an admin. You are now in the kick room".encode(Format)))

        print(users[index_to_kick].nickname, users[index_to_kick].group)
        return users[index_to_kick]  # Return the updated user object
    else:
        client.send(encrypt(f"Can't kick {name_to_kick}, user is not connected.".encode(Format)))
        return None  # Return None to indicate that the user was not found


# this function gets a user and writes his details to the user_data, if user already exist there, it changes his
# password if he asks to
def write_user_data(user):
    print("check1")
    try:
        with open("user_storage.txt", 'r+') as file:
            lines = file.readlines()
            updated_lines = []
            user_exists = False

            for line in lines:
                split_line = line.split(' ')
                if user.nickname == split_line[0]:
                    # Update the line with the new password
                    updated_line = f"{user.nickname} {user.password}\n"
                    updated_lines.append(updated_line)
                    user_exists = True
                else:
                    updated_lines.append(line)

            if not user_exists:
                # If user not found, append new user data to the end of the file
                updated_lines.append(f"{user.nickname} {user.password}\n")

            # Move file pointer to the beginning and write the updated lines back to the file
            file.seek(0)
            file.writelines(updated_lines)
            file.truncate()
    except FileNotFoundError:
        with open("user_storage.txt", 'a') as file:
            updated_lines = [f"{user.nickname} {user.password}\n"]
            # Move file pointer to the beginning and write the updated lines back to the file
            file.seek(0)
            file.writelines(updated_lines)
            file.truncate()
    print("check2")


# this function gets a nickname and password if a user with these details exist, it returns 0, if a user with that
# name but not the same password exist, it returns 1, else it reruns 2
def find_user_in_users(nickname, password):
    try:
        with open("user_storage.txt", 'r') as file:
            for line in file:
                split_line = line.split(' ')
                split_line[1] = split_line[1].rstrip('\n')
                if nickname == split_line[0] and password == split_line[1]:
                    return 0
                elif nickname == split_line[0]:
                    return 1
            return 2
    except:
        return 2


# this function gets a message, group and client and write the message that was sent by client in the group
# to the data storage
def write_data(message, group, client):
    with open("chat_storage.txt", 'a') as file:
        file.write(f"{encrypt(group.encode(Format))}:::{encrypt(users[clients.index(client)].nickname.encode(Format))}:::{encrypt(message.encode(Format))}\n")


# this function gets message and group and write to the data storage that the server sent message to group
def write_server_to_data(message, group):
    srv = "server"
    with open("chat_storage.txt", 'a') as file:
        file.write(f"{encrypt(group.encode(Format))}:::{encrypt(srv.encode(Format))}:::{encrypt(message.encode(Format))}\n")


# this function gets message and client and change the client room to be the room in the message
def switch_room(msg, client):
    global users, nicknames
    group = msg[4:]
    index = clients.index(client)
    prv_group = users[index].group
    users[index].group = group  # Update the user's group
    broadcast(f"{users[index].nickname} left the chat", prv_group)  # broadcast to the previous group that client left
    time.sleep(1.5)
    # broadcast to the new group that client join
    broadcast(f"{users[index].nickname} join the chat: {group}", group)


# this function gets a client and msg and change his password to be the password in msg
def change_password(client, msg):
    global users
    new_password = msg[9:]
    flag = True
    # if password is too short send it to the client
    if len(new_password) < 6:
        flag = False
        client.send(encrypt("could not update your password, password should be at least 6 chars long".encode(Format)))

    index = clients.index(client)
    name = users[index].nickname
    print("check3")
    with open("user_storage.txt", 'r+') as file:
        lines = file.readlines()
        updated_lines = []
        user_exists = False

        # look for the line where the user in
        for line in lines:
            if name in line:
                # Update the line with the new password
                updated_line = f"{name} {new_password}\n"
                updated_lines.append(updated_line)
                users[index].password = new_password
                user_exists = True
            else:
                updated_lines.append(line)

        if not user_exists:
            # If user not found, send it to the client
            flag = False
            client.send(encrypt("an error occurred, could not update your password".encode(Format)))

        # Move file pointer to the beginning and write the updated lines back to the file
        if flag:
            file.seek(0)
            file.writelines(updated_lines)
            file.truncate()
            client.send(encrypt(f"your password change to {new_password}".encode(Format)))


# this function gets a clients and sent him all the connected users and chat they are in
def show_connected_users(client):
    all_users = ""
    for user in users:
        if isAdmin(user):
            all_users = all_users + f"{user.nickname} in chat: {user.group} (admin)\n"
        else:
            all_users = all_users + f"{user.nickname} in chat: {user.group}\n"
    client.send(encrypt(all_users.encode(Format)))


# this function gets a client and message and send the file to all the people that should get it
def send_file(message, client):
    index = clients.index(client)
    parts = message.split()
    if len(parts) == 3:  # if the file was sent to specific user
        if isAdmin(users[clients.index(client)]):  # send it only if the admin send
            recipient_nickname = parts[2]
            file_name = parts[1]
            send_to(file_name, recipient_nickname, client)
        else:  # else print message
            client.send(encrypt("only admins can send file to specific users".encode(Format)))
    elif len(parts) == 2:  # if the file send to all the people send it one by one
        file_name = parts[1]
        for user in users:
            if user.group == users[index].group and user != users[index]:
                send_to(file_name, user.nickname, client)
    else:  # file transfer command is not valid
        client.send(encrypt("Invalid file transfer command. Usage: /send file <recipient_nickname> <file_name>".encode(Format)))


# this function gets a client, file name and a user name and send the file to this specific user
def send_to(file_name, recipient_nickname, client):
    index = clients.index(client)
    with open(file_name, "rb"):
        try:
            recipient_index = nicknames.index(recipient_nickname)
            recipient_client = clients[recipient_index]
            if recipient_nickname not in nicknames:  # user is not connected
                client.send(encrypt(f"Can't send file, {recipient_nickname} is not connected".encode(Format)))
            elif users[index].group != users[recipient_index].group:  # user is not in the group
                client.send(encrypt(f"Can't send file, {recipient_nickname} is not in this group".encode(Format)))
            else:  # send the file part by part
                recipient_client.send(encrypt(f"SEND FILE:{users[index].nickname}:sent you the file:{file_name}".encode(Format)))
                delimiter = b'####'  # we use this in order that the client understand when is the end of the file
                with open(file_name, "rb") as file:
                    while True:
                        chunk = file.read(1024)
                        if not chunk:
                            break
                        recipient_client.send(encrypt(chunk))
                        time.sleep(0.25)
                    recipient_client.send(encrypt(delimiter))
                write_data(f"{users[index].nickname} send the file {file_name} to {recipient_nickname}",
                           users[index].group, client)
        except ValueError:  # user in not connected
            client.send(encrypt(f"Can't send file, {recipient_nickname} is not connected".encode(Format)))
        except FileNotFoundError:  # file not found
            client.send(encrypt("can not find the file".encode(Format)))


receive()
