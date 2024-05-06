import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import *

def encrypt():
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    message = entry_message.get()
    ct_bytes = cipher.encrypt(pad(message.encode(), 16))
    entry_encrypted.insert(0, base64.b64encode(ct_bytes).decode('utf-8'))
    entry_key.insert(0, base64.b64encode(key).decode('utf-8'))

def decrypt():
    key = base64.b64decode(entry_key.get())
    ct_bytes = base64.b64decode(entry_encrypted.get())
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct_bytes), 16)
    entry_decrypted.insert(0, pt.decode('utf-8'))

def pad(s, block_size):
    padding = block_size - len(s) % block_size
    return s + bytes([padding]) * padding

def unpad(s, block_size):
    padding = s[-1]
    if padding > block_size:
        raise ValueError("Invalid padding")
    return s[:-padding]

root = Tk()
root.title("AES Encryption/Decryption")


font = ('Helvetica', 14)


padx = 10
pady = 5


Label(root, text="Message", font=font).grid(row=0+2, column=0, padx=padx, pady=pady, sticky='w')
entry_message = Entry(root, font=font, width=50)
entry_message.grid(row=0+2, column=1, padx=padx, pady=pady, sticky='w')

Label(root, text="Encrypted", font=font).grid(row=2+2, column=0, padx=padx, pady=pady, sticky='w')
entry_encrypted = Entry(root, font=font, width=50)
entry_encrypted.grid(row=1+2, column=1, padx=padx, pady=pady, sticky='w')

Label(root, text="Key", font=font).grid(row=1+2, column=0, padx=padx, pady=pady, sticky='w')
entry_key = Entry(root, font=font, width=50)
entry_key.grid(row=2+2, column=1, padx=padx, pady=pady, sticky='w')

Label(root, text="Decrypted", font=font).grid(row=3+2, column=0, padx=padx, pady=pady, sticky='w')
entry_decrypted = Entry(root, font=font, width=50)
entry_decrypted.grid(row=3+2, column=1, padx=padx, pady=pady, sticky='w')


Button(root, text="Encrypt", font=font, command=encrypt).grid(row=4+2, column=0, padx=padx, pady=pady, sticky='w')
Button(root, text="Decrypt", font=font, command=decrypt).grid(row=4+2, column=1, padx=padx, pady=pady, sticky='w')

root.mainloop()