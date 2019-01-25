import os
import sys
from optparse import OptionParser
import opssh.opssh as opssh


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
    op = opssh.onepasswordSSH(subdomain='my')
    op.add_keys_to_agent()


def download_key():
    parser = OptionParser()
    parser.add_option("-o", "--overwrite",
                      action="store_true", dest="overwrite", default=False,
                      help="Overwrite file if exists")

    (options, args) = parser.parse_args(sys.argv)

    if len(args) < 2:
        p, c = os.path.split(sys.argv[0])
        print("usage: {} <keyname>".format(c, file=sys.stderr))
        print("", file=sys.stderr)
        return 127

    names = args[1:]

    op = opssh.onepasswordSSH(subdomain='my')
    for name in names:
        op.save_private_key(name, overwrite=options.overwrite)
