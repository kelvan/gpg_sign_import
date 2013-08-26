# coding: utf-8
import sys
import email
import imaplib
import gpgme
from io import BytesIO
from getpass import getpass, getuser
import logging
import argparse
import socket

# configure logger
logger = logging.getLogger('import_gpg_signs')
ch = logging.StreamHandler(sys.stdout)
#ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.setLevel(logging.INFO)


def decrypt(msg):
    """ take msg, return decrypted msg as BytesIO
    """
    plaintext = BytesIO()
    cx.decrypt(BytesIO(bytes(msg.as_string(), 'ascii')), plaintext)
    plaintext.seek(0)
    return plaintext


# argparse stuff
parser = argparse.ArgumentParser(description='Load public keys from imaps server, decrypt with main key, import into gpg.\nHandy after signing parties.')

parser.add_argument('-s', '--server', metavar='host', required=True, 
                    type=str, nargs=1, help='imap server', dest='host')
parser.add_argument('-u', '--user', metavar='username', required=False, 
                    type=str, nargs=1, help='username, use systemuser as default', dest='user')
parser.add_argument('-m', '--mailbox', metavar='name', required=False, default='INBOX',
                    type=str, nargs=1, help='select mailbox, default is INBOX')
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

# imap part
host = args.host[0]
print(host)
logger.info('Connect to %s', host)
try:
    M = imaplib.IMAP4_SSL(host)
except socket.error as e:
    logger.fatal(e)
    sys.exit(1)

if args.user:
    user = args.user[0]
else:
    user = getuser()

logger.info('Login with user: %s', user)
try:
    rc, resp = M.login(user, getpass())
except imaplib.IMAP4.error as e:
    logger.fatal(e)
    sys.exit(2)

if not rc == 'OK':
    logger.error(resp)
    sys.exit(2)

mailbox = args.mailbox[0]
logger.info('Select mailbox: %s', mailbox)
rc, msg = M.select(mailbox)

if not rc == 'OK':
    logger.fatal('Selecting inbox failed: %s', msg[0])
    sys.exit(3)

rc, key_msg_uid = M.uid('search', None, 'HEADER Subject "Your signed PGP key"')
key_msg = key_msg_uid[0].split()

# gpg section
cx = gpgme.Context()

for uid in key_msg:
    rc, data = M.uid('fetch', uid, "(RFC822)")

    if not rc == 'OK':
        logger.warn(rc)
        continue

    email_body = data[0][1]
    mail = email.message_from_bytes(email_body)

    if not mail.get_content_maintype() == 'multipart':
        logger.warn('{0}: missing attachment'.format(uid))
        continue
    
    logger.info('{0} [{1}]'.format(mail['FROM'], uid))

    logger.debug('{0} [{1}]: start decrypt'.format(mail['FROM'], uid))
    d = decrypt(mail.get_payload()[1])
    logger.debug('{0}: decrypt finished'.format(uid))
    logger.debug('{0} [{1}]: start import'.format(mail['FROM'], uid))
    cx.import_(d)
    logger.debug('{0}: import finished'.format(uid))
