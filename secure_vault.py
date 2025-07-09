import tkinter as tk
import tkinter.font as font
from tkinter import filedialog,messagebox
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_file(file_path,password):
    password=password.encode()
    salt=os.urandom(16)
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key=kdf.derive(password)
    with open(file_path,"rb") as f:
        data=f.read()
    nonce=os.urandom(12)
    aesgcm=AESGCM(key)
    ciphertext=aesgcm.encrypt(nonce,data,None)
    encrypted_path=file_path + ".enc"
    with open(encrypted_path,"wb") as f:
        f.write(salt+nonce+ciphertext)
    return encrypted_path
def decrypt_file(file_path,password):
    password=password.encode()
    with open(file_path,"rb") as f:
        data=f.read()
    salt=data[:16]
    nonce=data[16:28]
    ciphertext=data[28:]
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    
    )
    key=kdf.derive(password)
    aesgcm=AESGCM(key)
    try:
        decrypted=aesgcm.decrypt(nonce,ciphertext,None)
        out_file=file_path.replace(".enc","_decrypted.txt")
        with open(out_file,"wb") as f:
            f.write(decrypted)
        return out_file
    except:
        return None
def browse_file():
    selected=filedialog.askopenfilename()
    if selected:
        file_path.set(selected)
def handle_encrypt():
    path=file_path.get()
    if not os.path.isfile(path) or not password.get():
        messagebox.showwarning("Missing info","valid file path and password required. ")
        return
    enc_path=encrypt_file(path,password.get())
    file_path.set(enc_path)
    messagebox.showinfo("Success",f"✅Encrypted\nSaved at :\n{enc_path}")
def handle_decrypt():
    path=file_path.get()
    if not os.path.isfile(path) or not password.get():
        messagebox.showwarning("Missing info","please give valid file path and password required.")
        return
    dec_path=decrypt_file(path,password.get())
    if dec_path:
        file_path.set(dec_path)
        messagebox.showinfo("Success",f"✔️Decrpted\nSaved at:\n{dec_path}")
    else:
        messagebox.showerror("Error","❌Wrong password or corrupted file.")
root=tk.Tk()
root.title("🔐File Vault")
root.geometry("500x300")
file_path=tk.StringVar()
password=tk.StringVar()
tk.Label(root,text="Enter File path :").pack()
tk.Entry(root,textvariable=file_path,width=60).pack()
tk.Button(root,text="Browse",command=browse_file).pack(pady=5)
tk.Label(root,text="Enter password :").pack()
tk.Entry(root,textvariable=password,show="*",width=40).pack()
bold_font = font.Font(size=8,weight="bold")
tk.Button(root,text="🔒Encrypt",command=handle_encrypt,bg="green",fg="white",font=bold_font,width=10).pack(pady=10)
tk.Button(root,text="🔓Decrypt",command=handle_decrypt,bg="blue",fg="white",font=bold_font,width=10).pack()
root.mainloop()