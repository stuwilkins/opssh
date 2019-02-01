import os
import sys
from argparse import ArgumentParser
import opssh.opssh as opssh


def _add_default_parser(parser):
    parser.add_argument("-d", "--domain", metavar='domain',
                        default='my',
                        help="1password domain to use")


def askpass():
    """This routine is run as SSH_ASKPASS to get a passphrase"""

    key = os.environ.get('SSH_KEY_ID', None)
    sd = os.environ.get('OP_SESSION_SUBDOMAIN', None)

    if key is None:
        raise RuntimeError("Environmental Variable for Key Not Set")

    if sd is None:
        raise RuntimeError("Environmental Variable for SubDomain Not Set")

    op = opssh.onepasswordSSH(subdomain=sd, verbose=False)
    print(op.get_passphrase(key), file=sys.stdout)


def add_keys_to_agent():

    parser = ArgumentParser(description='Add SSH keys stored in the 1password '
                                        'vault to ssh-agent')
    _add_default_parser(parser)

    parser.add_argument("-D", "--delete",
                        action="store_true", dest="delete", default=False,
                        help="Detete keys from agent before starting")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--all",
                       action="store_true", dest="all",
                       help="Add all keys to SSH agent")
    group.add_argument('keys', metavar='keyname', nargs="*",
                       default=list(),
                       help="Keyname to add to agent")

    args = parser.parse_args()

    op = opssh.onepasswordSSH(subdomain=args.domain)
    if args.all:
        op.add_keys_to_agent(delete=args.delete)
    else:
        op.add_keys_to_agent(keys=args.keys,
                             delete=args.delete)


def download_key():
    parser = ArgumentParser(description='Add ssh key to system')
    _add_default_parser(parser)

    parser.add_option("-o", "--overwrite",
                      action="store_true", dest="overwrite",
                      help="Overwrite file if exists")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--all",
                       action="store_true", dest="all",
                       help="Download and install  all keys.")
    group.add_argument('keys', metavar='keyname', nargs="*",
                       default=list(),
                       help="Keyname to add to agent")

    args = parser.parse_args()

    op = opssh.onepasswordSSH(subdomain=args.domain)

    if args.all:
        op.save_private_key(overwrite=options.overwrite)
    else:
        for name in args.keys:
            op.save_private_key(name, overwrite=options.overwrite)
