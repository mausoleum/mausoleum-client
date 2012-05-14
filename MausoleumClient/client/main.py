import pyinotify
import requests
from MausoleumClient.crypto.cipher import *
from MausoleumClient.crypto.symmetric import *
from MausoleumClient.crypto.pubkey import *
from Crypto.Hash import SHA512
from StringIO import StringIO
import json
import os
import binascii

SERVER_URL = 'http://mausoleum.mit.edu:5000/'
USERNAME = "Drew Dennison"
PASSWORD = "lolol"


class AllEventHandler(pyinotify.ProcessEvent):

    def process_IN_CLOSE_WRITE(self, event):
        print "CLOSE_WRITE event:", event.pathname

    def process_IN_CREATE(self, event):
        print "CREATE event:", event.pathname
        new_file(event.pathname)

    def process_IN_DELETE(self, event):
        print "DELETE event:", event.pathname

    def process_IN_MODIFY(self, event):
        print "MODIFY event:", event.pathname

def watch_for_changes(directory):
    ''' This function is given a directory and watches for changes to
    the directory. It is threaded  '''
    wm = pyinotify.WatchManager() 
    wm.add_watch(directory, pyinotify.ALL_EVENTS, rec=True)
    
    eh = AllEventHandler()

    notifier = pyinotify.ThreadedNotifier(wm, eh)

def shardify(file_path):
    basename = os.path.basename(file_path)
    return  '/'+basename[0]+"/"+basename[1]+"/"+basename


def generate_metadata(enc_data, IV, action, seq_num):
    hasher = SHA512.new()
    hasher.update(enc_data)
    meta = {"hash": hasher.hexdigest(), "iv": binascii.b2a_base64(IV), "action": action, "seq_num": seq_num}
    return json.dumps(meta)


def register_user(username, password):
    post_data = {"username":username, "password":password}
    r = requests.post(SERVER_URL+'register', post_data)
    print r.status_code, r.text
    
def loadPKCS():
    try:
        public = open('public.key')
        private = open('private.key')
    except IOError as e:
        print "generating and saving new RSA key pair"
        public, private = PKCSOne.generate()
        new_public = open('public.key', 'w')
        new_public.write(public)
        new_public.close()
        new_private = open('private.key', 'w')
        new_private.write(private)
        new_private.close()
    return PKCSOne(public, private)

def get_token(username, password):
    post_data = {"username":username, "password":password}
    r = requests.post(SERVER_URL+'get_token', post_data)
    
    return json.loads(r.text)['token']

def new_file(file_path, seq_num, token, PKCS):
    # generate new AES key
    (AES_key, IV) = BlockCipher.generate_ivs()
    # open file
    f = open(file_path, 'rb')
    aes = AESCTR(AES_key, IV)
    enc_data = aes.encrypt(f.read())

    metadata = generate_metadata(enc_data, IV, "PUT", seq_num)
    metadata_sig = binascii.b2a_base64(PKCS.sign(metadata))

    upload(shardify(file_path), enc_data, metadata, metadata_sig, token)
    
    # add key for yourself
    enc_aes = binascii.b2a_base64(PKCS.encrypt(AES_key))
    sig_aes = binascii.b2a_base64(PKCS.sign(AES_key))
    add_key(shardify(file_path), USERNAME, enc_aes, sig_aes, token)
    return AES_key, IV  # so you can share with others


def update_file(file_path):
    pass

def download_file(file_path, AES_key, IV, good_hash, token):
    enc_file = get(file_path, token)
    hasher = SHA512.new()
    hasher.update(enc_file)
    hash512 = hasher.hexdigest()
    if good_hash != hash512:
        raise Exception("The file contents have been tampered with")
    aes = AESCTR(AES_key, IV)
    plain_file = aes.decrypt(enc_file)
    return plain_file

def upload(file_path, enc_data, metadata, metadata_sig, token, user=None):
    post_data = {"path": file_path, "metadata": metadata, "metadata_signature": metadata_sig, "token": token}
    if user:
        post_data["user"] = user
    files = {'file': (file_path, StringIO(enc_data))} # having to use StringIO is a hack because requests is expecting a file object even though the documentation says it can accept a string
    r = requests.post(SERVER_URL+'file', post_data, files=files)
    r.raise_for_status()

def get(file_path, token, user=None):
    params = {"path": file_path,"token": token}
    if user:
        params['user'] = user
    r = requests.get(SERVER_URL+'file', params=params)
    r.raise_for_status()
    return r.content

def delete(file_path, metadata, metadata_sig, token):
    post_data = {"path": file_path,"metadata": metadata,"metadata_signature":metadata_sig, "token": token}
    r = requests.post(SERVER_URL+'delete', post_data)
    r.raise_for_status()

def get_events(timestamp, token):
    params = {"timestamp": timestamp,"token": token}
    r = requests.get(SERVER_URL+'events', params=params)
    r.raise_for_status()
    return r.content

def add_key(file_path, user, key, key_sig, token):
    post_data = {"path": file_path, "user": user, "key": key, "metadata_signature": key_sig,  "token": token}
    r = requests.post(SERVER_URL+'file/key', post_data)
    r.raise_for_status()

def get_key(file_path, user, token):
    params = {"path": file_path,"user": user, "token": token}
    r = requests.get(SERVER_URL+'file/key', params=params)
    r.raise_for_status()
    return r.content

def get_metadata(file_path, token):
    params = {"path": file_path,"token": token}
    r = requests.get(SERVER_URL+'file/metadata', params=params)
    r.raise_for_status()
    return json.loads(r.content)


def main(root_dir):
    watch_for_changes(root_dir)
    while True:
        # code to poll the server
        pass

def send_new_file(file_path, username, password, PKCS):
    token =  get_token(username, password)
    new_file(file_path, 1, token, pkcs) # 1 because the file is new
    
def receive_file(file_path, username, password, PKCS):
    token =  get_token(username, password)
    metadata = get_metadata(shardify(file_path), token)
    signature = binascii.a2b_base64(metadata['signature'])
    if not pkcs.verify(metadata['contents'],signature):
        raise Exception("Metadata has been tampered with!")
    contents = json.loads(metadata['contents'])

    action  = contents['action']
    iv  = binascii.a2b_base64(contents['iv'])
    hash512  = contents['hash']
    seq_num = contents['seq_num']

    enc_key = binascii.a2b_base64(get_key(shardify(file_path), username, token))
    aes_key = pkcs.decrypt(enc_key)

    return download_file(shardify(file_path), aes_key, iv, hash512, token)

if __name__ == '__main__':
    # register_user(USERNAME, PASSWORD)
    pkcs = loadPKCS()
    

    send_new_file('/tmp/testwatch', USERNAME, PASSWORD, pkcs)
    # now download the file
    print receive_file('/tmp/testwatch', USERNAME, PASSWORD, pkcs)

    # main('/tmp')
    
    
