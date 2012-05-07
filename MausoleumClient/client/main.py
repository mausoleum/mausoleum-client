import pyinotify
import requests

class AllEventHandler(pyinotify.ProcessEvent):

    def process_IN_CLOSE_WRITE(self, event):
        print "CLOSE_WRITE event:", event.pathname

    def process_IN_CREATE(self, event):
        print "CREATE event:", event.pathname

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

def main(root_dir):
    watch_for_changes(root_dir)
    
if __name__ == '__main__':
    main('/tmp')
