import pyinotify
import requests
from MausoleumClient.crypto.cipher import *
from MausoleumClient.crypto.symmetric import *

SERVER_URL = 'http://mausoleum.mit.edu:5000/'

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

def register_user(username, password):
    post_data = {"username":username, "password":password}
    r = requests.post(SERVER_URL+'register', post_data)
    print r.status_code, r.text
    

def get_token(username, password):
    post_data = {"username":username, "password":password}
    r = requests.post(SERVER_URL+'get_token', post_data)
    print r.status_code, r.text

def new_file(file_path):
    # generate new AES key
    (AES_key, IV) = BlockCipher.generate_ivs()
    
    # open file
    f = open(file_path, 'r')
    aes = AESCTR(AES_key, IV)
    enc_data = aes.encrypt(f.read())
    print repr(enc_data)


def main(root_dir):
    watch_for_changes(root_dir)
    while True:
        # code to poll the server
        pass
    
if __name__ == '__main__':
    # register_user('Drew Dennison', 'lolol')
    get_token("Drew Dennison", "lolol")
    new_file('/tmp/testwatch')
    main('/tmp')
