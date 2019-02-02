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
                    print("1password cli failed (err={}) ...."
                        .format(rtn.returncode), file=sys.stderr)
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
                self._opkey = bytearray(self._opkey, self._encoding)
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


class onepasswordSSH(onepassword):
    def __init__(self, *args, keys_path=None, **kwargs):
        super().__init__(*args, **kwargs)

        self._keys = None

        if keys_path is None:
            self._keys_path = os.path.join(os.environ['HOME'], ".ssh")
        else:
            self._keys_path = keys_path

        if self._verbose:
            print("Using SSH path \"{}\" ....".format(self._keys_path),
                file=sys.stderr)

        self._private_keys = None

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

            name = None
            passphrase = None
            for field in fields:
                if (field['t'] == 'KeyName') and \
                   (field['k'] == 'string'):
                    name = field['v']
                if (field['t'] == 'Passphrase') and \
                   (field['k'] == 'concealed'):
                    passphrase = field['v']

            if (name is not None) and (passphrase is not None):
                if self._verbose == 2:
                    print("Found SSH key uuid=\"{}\" name=\"{}\" ....".format(
                        item['uuid'], name),
                        file=sys.stderr)

                keys[name] = {'passphrase': passphrase}
            else:
                print("Error parsing key information (uuid=\"{}\") ...."
                      .format(item['uuid']), file=sys.stderr)

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
        env['OP_SESSION_{}'.format(self._subdomain)] = \
            self._opkey.decode(self._encoding)
        env['OP_SESSION_SUBDOMAIN'] = self._subdomain
        env['OP_SESSION_TIMEOUT'] = str(self._timeout)
        env['SSH_KEY_ID'] = key

        if self._verbose:
            print("Adding key \"{}\" to ssh-agent .... ".format(key),
                  file=sys.stderr, end='')
        rtn = subprocess.run(cmd, shell=False, env=env,
                             timeout=self._timeout,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if self._verbose:
            if rtn.returncode:
                print("FAILED.", file=sys.stderr)
                print("ERR = ", file=sys.stderr, end='')
                print(rtn.stderr.decode(self._encoding), file=sys.stderr)
            else:
                print("Done.", file=sys.stderr)

    def agent_delete_keys(self):
        """Call ssh-add and delete stored keys"""
        cmd = ['ssh-add', '-D']
        print("Calling ssh-add to delete current keys .... ", end='',
              file=sys.stderr)
        rtn = subprocess.run(cmd, shell=False, timeout=self._timeout,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if self._verbose:
            if rtn.returncode:
                print("FAILED.", file=sys.stderr)
                print("ERR = ", file=sys.stderr, end='')
                print(rtn.stderr.decode(self._encoding), file=sys.stderr)
            else:
                print("Done.", file=sys.stderr)

        if rtn.returncode == 0:
            return True

        return False

    def add_keys_to_agent(self, keys=None, delete=False):
        """Add keys to ssh agent"""
        if self._keys is None:
            self.get_keys()

        if delete:
            self.agent_delete_keys()

        for name, vals in self._keys.items():
            if keys is None:
                self._ssh_add(name, vals['passphrase'])
            else:
                if name in keys:
                    self._ssh_add(name, vals['passphrase'])

    def _get_private_keys(self):
        """Get the ssh private key files"""
        uuids = self.find_items_tag('SSH_KEY_FILE')
        if not len(uuids):
            raise RuntimeError("Unable to find SSH keys in database")

        items = self.get_items(uuids)
        keys = dict()
        for item in items:
            # print(json.dumps(item, sort_keys=True, indent=4))
            fields = [sect['fields']
                      for sect in item['details']['sections']
                      if 'fields' in sect]
            name = None
            for field in fields:
                if len(field) != 1:
                    raise RuntimeError("Error parsing fields, expected "
                                       "only one")
                field = field[0]
                if (field['t'] == 'KeyName') and (field['k'] == 'string'):
                    name = field['v']

            keys[name] = {'uuid': item['uuid'],
                          'filename': item['details']
                                          ['documentAttributes']
                                          ['fileName']}

        self._private_keys = keys

    def get_private_key(self, key_id):
        if self._private_keys is None:
            self._get_private_keys()

        if key_id not in self._private_keys:
            raise RuntimeError("Unable to find key \"{}\" in vault".format(
                key_id))

        return self.get_documents([self._private_keys[key_id]['uuid']])

    def save_private_key(self, key_id, overwrite=False):
        """Save thr private key to a file"""

        key = self.get_private_key(key_id)
        filename = self._private_keys[key_id]['filename']
        filename = os.path.join(self._keys_path, filename)

        if os.path.isfile(filename) and not overwrite:
            print("File \"{}\" exists, not overwriting ....".format(filename),
                  file=sys.stderr)
            return False

        if overwrite:
            print("Overwriting ", file=sys.stderr, end='')
        else:
            print("Writing ", file=sys.stderr, end='')

        print("\"{}\" as private key \"{}\" ....".format(filename, key_id),
              file=sys.stderr)

        with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o600),
                  'wb') as file:
            file.write(key)
