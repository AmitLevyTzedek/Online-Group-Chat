import socket
import threading
import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

host = '127.0.0.1'
port = 55555
Format = 'utf-8'
ADDR = (host, port)
number_of_admins = 3
delimiter = b'####'
flag = 0
count_rows_file = 0
file_name = ""

# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'

nickname = input("choose a nickname: ")  # gets a nickname
while len(nickname) < 4:
    print("nickname length should be at least 4")
    nickname = input("choose a nickname: ")

password = input("choose a password: ")  # gets a password
while len(password) < 6:
    print("password length should be at least 6")
    password = input("choose a password: ")

group_name = input("choose a room name: ")  # gets a group's name

count = 0

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # connect to server
client_socket.connect((host, port))


# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    plaintext_bytes = plaintext.encode(Format)  # Encode the plaintext string to bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode(Format)


# receive function
def receive():
    global nickname, password, count, group_name, flag, count_rows_file, file_name

    # gets a message, check them and acts accordingly
    while True:
        try:
            enc_message = client_socket.recv(1024)
            message = decrypt(enc_message)
            if message == "Enter nickname:":  # gets a nickname
                client_socket.send(encrypt(nickname))
                count += 1
            elif message == "There is other user with this name, enter other nickname:":  # problem with this nickname
                print("There is other user with this name, enter other nickname:")
                new_nickname = input("choose a nickname: ")
                client_socket.send(encrypt(new_nickname))
                nickname = new_nickname
                print("Updated nickname:", nickname)
            elif message == "Enter password:":  # gets a password
                client_socket.send(encrypt(password))
            elif message == "Enter Group name:":  # gets a room name
                client_socket.send(encrypt(group_name))
            elif message == "You were kicked from the group by an admin. You are now in the kick room":
                print(
                    "You were kicked from the group by an admin. You are now in the kick room")  # user kicked by the admin
            elif message.startswith("SEND FILE"):  # user gets a file
                flag = 1
                file_name = message.split("sent you the file:")[1]
                sender = message.split(":")[1]
                print(sender, "send you the file:", file_name)
                endf = file_name.split('.')[1]
                file_name = file_name.split('.')[0]
                new_file_name = f"{file_name}_{nickname}"
                add_to_file = 1
                while os.path.exists(new_file_name):
                    new_file_name = f"{new_file_name}({add_to_file})"
                    add_to_file += 1
                new_file_name = f"{new_file_name}.{endf}"
                create_file(new_file_name)
            else:  # regular message
                print(message)
        except:  # an error occurred
            print("an error occurred")
            client_socket.close()
            break


# this function gets a nickname and a password and check if it's an admin
def isAdmin(nick, passw):
    try:
        with open("user_storage.txt", 'r') as file:
            # Read the first lines (the admins are in the first lines of the file)
            for i in range(number_of_admins):
                line = file.readline()
                # check if user is an admin
                if nick in line and passw in line:
                    return True
            return False
    except:
        return False


# write function
def write():
    global count
    while True:
        if count == 1:
            time.sleep(4)  # delay when firstly enter a room
            count = 2
        else:
            time.sleep(1)  # delay to rate limit mechanism
        message = f'{nickname}: {input("")}'  # gets a message
        # if the users is an admin
        if isAdmin(nickname, password):
            if message[len(nickname) + 2:].startswith('/'):  # if the message is a command
                if message[len(nickname) + 2:].startswith('/kick'):  # kick a user
                    client_socket.send(encrypt(f"KICK {message[len(nickname) + 2 + 6:]}"))
                elif message[len(nickname) + 2:].startswith('/switch room'):  # switch room
                    client_socket.send(encrypt(f"SWC {message[len(nickname) + 2 + 13:]}"))
                elif message[len(nickname) + 2:].startswith('/switch password'):  # switch password
                    client_socket.send(encrypt(f"PASSWORD {message[len(nickname) + 2 + 17:]}"))
                elif message[len(nickname) + 2:].startswith('/connected users'):  # see connected users and their rooms
                    client_socket.send(encrypt(f"CON_USERS {message[len(nickname) + 2 + 17:]}"))
                elif message[len(nickname) + 2:].startswith('/send file'):  # send file to user\users
                    client_socket.send(encrypt(f"FILE {message[len(nickname) + 2 + 11:]}"))
            else:  # regular message
                client_socket.send(encrypt(message))
        else:  # if the user is not an admin
            if message[len(nickname) + 2:].startswith('/switch room'):  # switch room
                client_socket.send(encrypt(f"SWC {message[len(nickname) + 2 + 13:]}"))
            elif message[len(nickname) + 2:].startswith('/switch password'):  # switch password
                client_socket.send(encrypt(f"PASSWORD {message[len(nickname) + 2 + 17:]}"))
            elif message[len(nickname) + 2:].startswith('/connected users'):  # see connected users and their rooms
                client_socket.send(encrypt(f"CON_USERS {message[len(nickname) + 2 + 17:]}"))
            elif message[len(nickname) + 2:].startswith('/send file'):  # send file to user\users
                client_socket.send(encrypt(f"FILE {message[len(nickname) + 2 + 11:]}"))
            else:  # regular message
                client_socket.send(encrypt(message))


# this function gets a file name and create file with message gets from server
def create_file(new_file_name):
    with open(new_file_name, 'w') as file:
        while True:  # Open the file in 'append binary' mode
            enc_message = client_socket.recv(1024)
            message = decrypt(enc_message)
            if message.endswith("####"):
                break
            file.write(message.strip('\n'))  # Write the received file chunk along with newline character
    updated_lines = []
    countl = 1
    with open(new_file_name, 'r') as file:
        for line in file:
            if countl % 2 == 1:
                updated_lines.append(line.strip('\n'))
            countl += 1
    with open(new_file_name, 'w') as file:
        for line in updated_lines:
            file.write(f"{line}\n")


receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
