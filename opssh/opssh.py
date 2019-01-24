import os
import sys
import json
import subprocess

class onepassword:
    def __init__(self, subdomain='my', verbose=True):
        self._subdomain = subdomain
        self._opkey = os.environ.get('OP_SESSION_{}'.format(self._subdomain))
        self._items = None
        self._verbose = verbose

        # If we haven't authenticated at the shell, authenticate

        if self._opkey is None:
            # authenticate
            if self._verbose:
                print("Starting authentication with 1password ....",
                    file=sys.stderr)
            self._get_token()
        else:
            if self._verbose:
                print("Using previous 1password authentication ....",
                    file=sys.stderr)

        # Now get items so we can search

        self._get_list()

    def _run_op(self, cmd, input=None):
        """Run subprocess to talk to 1password"""

        if input is not None:
            input = bytearray(input, 'utf-8')

        rtn = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE,
                             input=input)
        if rtn.returncode != 0:
            raise RuntimeError(
                "1password cli failed (err={})".format(rtn.returncode))

        return rtn.stdout


    def _get_token(self):
        """Get a token from 1password"""

        cmd = ['op', 'signin', self._subdomain, '--output=raw']
        self._opkey = self._run_op(cmd).lstrip().rstrip()

    def _get_list(self):
        """List all items in the vault"""
        cmd = ['op', 'list', 'items']
        p = self._run_op(cmd, self._opkey)

        # Now parse JSON

        self._items = json.loads(p)
        #print(json.dumps(self._items, sort_keys=True, indent=4))

    def get_items(self, uuids):
        """Get Item from the vault based on uuid"""

        op = list()
        for uuid in uuids:
            cmd = ['op', 'get', 'item', uuid]
            p = self._run_op(cmd, self._opkey)
            op.append(json.loads(p))

        #print(json.dumps(op, sort_keys=True, indent=4))
        return op


    def find_items_tag(self, tag):
        """Find an item based on entry to """

        objs = [obj for obj in self._items if
                any([t == tag for t in obj['overview'].get('tags', [])])]

        #print(json.dumps(objs, sort_keys=True, indent=4))
        return [obj['uuid'] for obj in objs]


class onepasswordSSH(onepassword):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._keys = None
        self._keys_path = os.path.join(os.environ['HOME'], ".ssh/")

    def get_keys(self):
        """Get the SSH keys from the vault"""
        uuids = self.find_items_tag('SSH_KEY')
        if not len(uuids):
            raise RuntimeError("Unable to find SSH keys in database")

        items = self.get_items(uuids)
        keys = dict()
        for item in items:
            fields = [sect['fields']
                      for sect in item['details']['sections']
                      if 'fields' in sect]
            if len(fields) != 1:
                raise RuntimeError("More than one fields in key.")
            fields = fields[0]

            for field in fields:
                if (field['t'] == 'KeyName') and (field['k'] == 'string'):
                    name = field['v']
                if (field['t'] == 'Passphrase') and (field['k'] == 'string'):
                    passphrase = field['v']

            if self._verbose:
                print("Found SSH key \"{}\" ....".format(name),
                      file=sys.stderr)

            keys[name] = {'passphrase': passphrase}

        self._keys = keys

    def get_passphrase(self, keyid):
        """Return the passphrase of a key"""
        if self._keys is None:
            self.get_keys()

        return self._keys[keyid]['passphrase']

    def _ssh_add(self, key, passphrase):
        cmd = ['ssh-add', '-q',
               os.path.join(self._keys_path, key)]
        env = os.environ.copy()
        env['SSH_ASKPASS'] = 'opssh_askpass'
        env['DISPLAY'] = 'foo'
        env['OP_SESSION_{}'.format(self._subdomain)] = self._opkey
        env['OP_SESSION_SUBDOMAIN'] = self._subdomain
        env['SSH_KEY_ID'] = key

        if self._verbose:
            print("Adding key \"{}\" to ssh-agent .... ".format(key),
                    file=sys.stderr, end='')
        rtn = subprocess.run(cmd, shell=False, env=env,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if self._verbose:
            if rtn.returncode:
                print("FAILED.", file=sys.stderr)
                print("ERR = ", file=sys.stderr, end='')
                print(rtn.stderr, file=sys.stderr)
            else:
                print("Done.", file=sys.stderr)


    def add_keys_to_agent(self):
        """Add keys to ssh agent"""
        if self._keys is None:
            self.get_keys()

        for name, vals in self._keys.items():
            self._ssh_add(name, vals['passphrase'])

