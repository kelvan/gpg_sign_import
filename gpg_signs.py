#!/usr/bin/python
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
description = """Load public keys from IMAPS server, decrypt with main key,
import into gpg.\nHandy after signing parties."""

parser = argparse.ArgumentParser(description=description)
parser.add_argument('-s', '--server', metavar='host', required=True,
                    type=str, nargs=1, help='imap server', dest='host')
parser.add_argument('-u', '--user', metavar='username', required=False,
                    type=str, nargs=1, dest='user',
                    help='username, use systemuser as default')
parser.add_argument('-m', '--mailbox', metavar='name', required=False,
                    default=['INBOX'], type=str, nargs=1,
                    help='select mailbox, default is INBOX')
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

# imap part
host = args.host[0]
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

rc, key_msg_uid = M.uid('search', None, 'HEADER Subject "PGP key"')
key_msg = key_msg_uid[0].split()

# gpg section
cx = gpgme.Context()

for uid in reversed(key_msg):
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
    payload = mail.get_payload()
    for attachment in payload:
        logger.debug(attachment.get_content_type())
        if not attachment.get_content_type() == 'application/octet-stream':
            continue

        try:
            d = decrypt(attachment)
            logger.debug('{0}: decrypt finished'.format(uid))
            logger.debug('{0} [{1}]: start import'.format(mail['FROM'], uid))
            cx.import_(d)
            logger.debug('{0}: import finished'.format(uid))
        except gpgme.GpgmeError as e:
            logger.debug(e)
