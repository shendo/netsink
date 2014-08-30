import SocketServer
import thread

import irc.client

from netsink.config import ModuleConfig
from netsink.modules import ircserver

def test_irc():
    server = SocketServer.TCPServer(('', 0), ircserver.IRCHandler)
    server.cfg = ModuleConfig('irc.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = irc.client.IRC()
    conn = client.server().connect('127.0.0.1', server.socket.getsockname()[1], 'nickname')
    conn.join("#testchan", key="12345")
    conn.privmsg("#testchan", "ready for tasking")
    # drain response messages
    for _ in range(6):
        client.process_once(0.015)
    conn.close()
