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
    metadata_sig = PKCS.sign(metadata)

    upload(shardify(file_path), enc_data, metadata, metadata_sig, token)
    
    # add key for yourself
    enc_aes = binascii.b2a_base64(PKCS.encrypt(AES_key))
    sig_aes = binascii.b2a_base64(PKCS.sign(AES_key))
    add_key(shardify(file_path), USERNAME, enc_aes, sig_aes, token)
    return AES_key, IV  # so you can share with others


def update_file(file_path):
    pass

def download_file(file_path, AES_key, IV, PKCS):
    enc_file = get(shardify(file_path), token)
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

def get_key(file_path, token, user=None):
    params = {"path": file_path,"token": token}
    if user:
        params['user'] = user
    r = requests.get(SERVER_URL+'file/key', params=params)
    r.raise_for_status()
    return r.content

def get_metadata(file_path, token):
    params = {"path": file_path,"token": token}
    r = requests.get(SERVER_URL+'file/metadata', params=params)
    r.raise_for_status()
    return json.loads(r.text)









def main(root_dir):
    watch_for_changes(root_dir)
    while True:
        # code to poll the server
        pass
    
if __name__ == '__main__':
    # register_user('Drew Dennison', 'lolol')
    public, private = PKCSOne.generate()
    # print public
    # print private
    pkcs = PKCSOne(public, private)

    token =  get_token("Drew Dennison", "lolol")
    aes_key, iv  =  new_file('/tmp/testwatch', 1, token, pkcs)
    print download_file('/tmp/testwatch', aes_key, iv, token)

    # main('/tmp')
    
    # upload("/t/e/testing.pdf", "this is not encrypted data but will be soon", "all the metadata", "metadata signature", token)
    # print get("/t/e/testing.pdf", token)
    # delete("/t/e/testing.pdf", "metadata", "metadata sig", token)
    # print get("/t/e/testing.pdf", token)
    # print add_key("/t/e/testing.pdf", "Drew Dennison", "This is a super secret key :)", token)
    # print get_events(1136871308, token)
    # print get_key("/t/e/testing.pdf", token)
