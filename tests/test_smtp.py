import email.utils
from email.mime.text import MIMEText
import SocketServer
import smtplib
import thread

from netsink.config import ModuleConfig
from netsink.modules import smtp

def test_smtp():
    server = SocketServer.TCPServer(('', 0), smtp.SMTPHandler)
    server.cfg = ModuleConfig('smtp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = smtplib.SMTP('127.0.0.1', server.socket.getsockname()[1])
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    # returns dictionary of failed recipients
    assert not client.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    client.quit()
    
                   
    
    