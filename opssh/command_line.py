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

    usage="usage: %prog [options] [[keyname] ..]"

    parser = OptionParser(usage=usage)
    parser.add_option("-a", "--all",
                      action="store_true", dest="all", default=False,
                      help="Add all keys to SSH agent")
    parser.add_option("-D", "--delete",
                      action="store_true", dest="delete", default=False,
                      help="Detete keys from agent before starting")

    (options, args) = parser.parse_args(sys.argv)

    if (len(args) < 2) and not options.all:
        print(parser.print_help(), file=sys.stderr)
        return 127

    names = args[1:]

    op = opssh.onepasswordSSH(subdomain='my')
    if options.all:
        op.add_keys_to_agent(delete=options.delete)
    else:
        op.add_keys_to_agent(keys=names, delete=options.delete)


def download_key():
    usage="usage: %prog [options] [[keyname] ..]"

    parser = OptionParser(usage=usage)
    parser.add_option("-o", "--overwrite",
                      action="store_true", dest="overwrite", default=False,
                      help="Overwrite file if exists")
    parser.add_option("-a", "--all",
                      action="store_true", dest="all", default=False,
                      help="Add all keys")

    (options, args) = parser.parse_args(sys.argv)

    if (len(args) < 2) and not options.all:
        print(parser.print_help(), file=sys.stderr)
        return 127

    names = args[1:]

    op = opssh.onepasswordSSH(subdomain='my')
    for name in names:
        op.save_private_key(name, overwrite=options.overwrite)
