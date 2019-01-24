import os, sys
import opssh.opssh as opssh

def askpass():
    """This routine is run as SSH_ASKPASS to get a passphrase"""
    #print(os.environ, file=sys.stderr)
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
