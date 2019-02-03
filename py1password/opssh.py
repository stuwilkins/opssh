import os
import sys
import json
import subprocess
from .op import onepassword

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
        env['SSH_ASKPASS'] = 'op-askpass'
        env['DISPLAY'] = 'foo'
        env['OP_SESSION_{}'.format(self._subdomain)] = \
            self._opkey.decode(self._encoding)
        env['OP_SESSION_SUBDOMAIN'] = self._subdomain
        env['OP_SESSION_TIMEOUT'] = str(self._timeout)
        env['SSH_KEY_ID'] = key

        if self._verbose:
            self._print("Adding key \"{}\" to ssh-agent".format(key))
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
        if self._verbose:
            self._print("Calling ssh-add to delete current keys")

        cmd = ['ssh-add', '-D']
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
