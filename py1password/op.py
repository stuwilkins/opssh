import os
import sys
import json
import subprocess


class onepassword:
    def __init__(self, subdomain='my', verbose=False, quiet=False,
                 timeout=60, login_tries=5, encoding='utf-8'):
        self._subdomain = subdomain
        self._encoding = encoding
        self._items = None
        self._timeout = timeout
        self._login_tries = login_tries

        self._opkey = os.environ.get('OP_SESSION_{}'.format(self._subdomain))
        if self._opkey is not None:
            self._opkey = bytearray(self._opkey, self._encoding)

        self._verbose = 1
        if verbose:
            self._verbose = 2
        if quiet:
            self._verbose = 0

        # If we haven't authenticated at the shell, authenticate

        if self._opkey is not None:
            if self._verbose:
                print("Using previous 1password authentication ....",
                      file=sys.stderr)

        # Now get items so we can search

        self._get_list('items')

    def _print(self, txt, col=65):
        print('{message:.<{width}}'.format(message=txt + ' ', width=col),
              end=' ', file=sys.stderr)

    def _run_op(self, cmd):
        """Run subprocess to talk to 1password"""

        rtncode = 127
        while(rtncode != 0):
            rtn = subprocess.run(cmd, shell=False,
                                 timeout=self._timeout,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 input=self._opkey)
            if (self._verbose == 2) and (rtn.stderr != b''):
                print(rtn.stderr.decode(self._encoding), end='',
                      file=sys.stderr)
            rtncode = rtn.returncode
            if rtncode != 0:
                if self._verbose == 2:
                    print("1password cli failed (err={}) ...." .format(
                        rtn.returncode), file=sys.stderr)
                print("Authenticating with 1password ....",
                      file=sys.stderr)
                self._get_token()

        return rtn.stdout

    def _get_token(self):
        """Get a token from 1password"""

        cmd = ['op', 'signin', self._subdomain, '--output=raw']

        # copy the env and remove the key
        env = os.environ.copy()
        env.pop('OP_SESSION_{}'.format(self._subdomain), None)

        # Now attempt login
        tries = self._login_tries
        while tries:
            rtn = subprocess.run(cmd, shell=False,
                                 timeout=self._timeout,
                                 stdout=subprocess.PIPE)
            if rtn.returncode == 0:
                # We have a login
                key = rtn.stdout
                if isinstance(key, bytearray):
                    key = key.decode(self._encoding)
                self._opkey = rtn.stdout.lstrip().rstrip()
                #self._opkey = bytearray(self._opkey, self._encoding)
                return

            tries -= 1

        # We should not get here
        raise RuntimeError("Unable to login to 1password after {} tries"
                           .format(self._login_tries))

    def _get_list(self, kind):
        """List all items in the vault"""
        cmd = ['op', 'list', kind]
        p = self._run_op(cmd)

        # Now parse JSON

        self._items = json.loads(p)

    def get_items(self, uuids):
        """Get Item from the vault based on uuid"""

        op = list()
        for uuid in uuids:
            cmd = ['op', 'get', 'item', uuid]
            p = self._run_op(cmd)
            op.append(json.loads(p))

        return op

    def get_documents(self, uuids):
        """Get a document from the vault"""

        op = list()
        for uuid in uuids:
            cmd = ['op', 'get', 'document', uuid]
            p = self._run_op(cmd)
            op.append(p)

        return op

    def find_items_tag(self, tag):
        """Find an item based on entry to """

        objs = [obj for obj in self._items if
                any([t == tag for t in obj['overview'].get('tags', [])])]

        # print(json.dumps(objs, sort_keys=True, indent=4))
        return [obj['uuid'] for obj in objs]


