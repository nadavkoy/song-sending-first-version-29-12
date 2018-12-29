import socket
from AES import *
from KeyGenerator import *
import pickle
import os

from pygame import mixer

KEY = os.urandom(16)


class Client(object):
    """ creating client """
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 4500))
        self.aes = AESCrypt()
        self.rsa = Cryptonew()
        self.public = ''

        self.song = ''

    def unpack(self, data):
        return pickle.loads(data.decode('base64'))

    def pack(self, data):
        return pickle.dumps(data).encode('base64')


def send_key(client):
    """ sends encryption key with the public key """
    client.public = client.client_socket.recv(1024)  # receiving public
    client.public = client.unpack(client.public)  # unpacking
    encrypted_key = client.rsa.encrypt(KEY, client.public)  # encrypting key with public
    client.client_socket.send(encrypted_key)  # sending key
    response = client.client_socket.recv(1024)  # receiving server's confirmation

def encrypt_request(client, request):
    """ encrypts client's request """
    return client.aes.encryptAES(KEY, request)


def decrypt_response(client, response):
    """ decrypts server's response """
    return client.aes.decryptAES(KEY, response)

def play_song(song):
    """ plays song """
    mixer.init()
    mixer.music.load(song)
    mixer.music.play()

def get_song(client):
    packets_num = int(client.client_socket.recv(1024))
    client.client_socket.send('number of packets received successfully.')
    print packets_num

    for i in range(packets_num):
        packet = client.client_socket.recv(1024)
        client.song += packet
        client.client_socket.send('packet received successfully.')

    new_file = open('new_song.mp3', 'wb')
    new_file.write(client.song)
    new_file.close()

def main():
    client = Client()
    send_key(client)
    get_song(client)
    play_song("new_song.mp3")
    while True:

        """name = encrypt_request(client, raw_input())
        client.client_socket.send(name)
        response = client.client_socket.recv(1024)
        print decrypt_response(client, response)
        """




if __name__ == '__main__':
    main()