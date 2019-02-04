import os
import sys
import subprocess
from .op import onepassword


class onepasswordSSH(onepassword):
    def __init__(self, *args, keys_path=None, **kwargs):
        super().__init__(*args, **kwargs)

        if keys_path is None:
            self._keys_path = os.path.join(os.environ['HOME'], ".ssh")
        else:
            self._keys_path = keys_path

        if self._verbose:
            print("Using SSH path \"{}\" ....".format(self._keys_path),
                  file=sys.stderr)

    def get_keys_info(self):
        """Get the SSH keys from the vault"""
        uuids = self.find_items_tag('SSH_KEY')
        if not len(uuids):
            raise RuntimeError("Unable to find SSH keys in database")

        keys = dict()
        for uuid in uuids:
            name, info = self._get_key_info(uuid)
            keys[name] = info

        return keys

    def get_passphrase(self, uuid):
        """Get the pasphrase of a SSH key given UUID"""
        name, info = self._get_key_info(uuid)
        return info['passphrase']

    def _get_key_info(self, uuids):
        items = self.get_items([uuids])

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
                    self._print("SSH key uuid=\"{}\" name=\"{}\""
                                .format(item['uuid'], name))
                    print("FOUND", file=sys.stderr)

                keys = {'passphrase': passphrase, 'uuid': item['uuid']}
            else:
                if self._verbose == 2:
                    print("ERROR", file=sys.stderr)

        return name, keys

    def _ssh_askpass(self, cmd, uuid):
        """Run a command with the askpass setup for vault"""
        env = os.environ.copy()
        env['SSH_ASKPASS'] = 'op-askpass'
        env['DISPLAY'] = 'foo'
        env['OP_SESSION_{}'.format(self._subdomain)] = \
            self._opkey.decode(self._encoding)
        env['OP_SESSION_SUBDOMAIN'] = self._subdomain
        env['OP_SESSION_TIMEOUT'] = str(self._timeout)
        env['SSH_KEY_UUID'] = uuid

        rtn = subprocess.run(cmd, shell=False, env=env,
                             timeout=self._timeout,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        return rtn

    def _ssh_add(self, uuid, key):
        if self._verbose:
            self._print("Adding key \"{}\" to ssh-agent".format(key))

        cmd = ['ssh-add', os.path.join(self._keys_path, key)]

        rtn = self._ssh_askpass(cmd, uuid)

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
        keys = self.get_keys_info()

        if delete:
            self.agent_delete_keys()

        if keys is None:
            for name, vals in keys.items():
                self._ssh_add(vals['uuid'], name)
        else:
            for name, vals in keys.items():
                if name in keys:
                    self._ssh_add(vals['uuid'], name)

    def get_private_keys(self):
        """Get the ssh private key files"""
        uuids = self.find_items_tag('SSH_KEY_FILE')
        if not len(uuids):
            raise RuntimeError("Unable to find SSH keys in database")

        items = self.get_items(uuids)
        keys = dict()
        for item in items:
            if 'details' not in item:
                continue
            if 'sections' not in item['details']:
                continue
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

        return keys
        # return self.get_documents([keys[key_id]['uuid']])

    def save_ssh_keys(self, key_names=None, overwrite=False):
        """Save the private key to a file"""
        private_keys = self.get_private_keys()
        public_keys = self.get_keys_info()

        # If none get all keys found
        if key_names is None:
            key_names = private_keys.keys()

        for key_id in key_names:
            _public_key = True

            if key_id not in private_keys:
                raise RuntimeError("Unable to find private key \"{}\" in vault"
                                   .format(key_id))
            if key_id not in public_keys:
                _public_key = False
                if self._verbose == 2:
                    print("Unable to find public key passphrase \"{}\" "
                          "in vault".format(key_id), file=sys.stderr)

            # if self._verbose == 2:
            #     print("Private key UUID = {}"
            #           .format(private_keys[key_id]['uuid']), file=sys.stderr)
            #     if _public_key:
            #         print("Public  key UUID = {}"
            #               .format(public_keys[key_id]['uuid']),
            #               file=sys.stderr)

            private_filename = private_keys[key_id]['filename']
            private_filename = os.path.join(self._keys_path, private_filename)

            if os.path.isfile(private_filename) and not overwrite:
                if self._verbose:
                    self._print("File \"{}\" exists"
                                .format(os.path.basename(private_filename)))
                    print("FAILED", file=sys.stderr)
            else:
                _data = self.get_documents([private_keys[key_id]['uuid']])[0]

                if self._verbose:
                    self._print("Writing private key \"{}\""
                                .format(os.path.basename(private_filename)))

                with open(os.open(private_filename,
                                  os.O_CREAT | os.O_WRONLY,
                                  0o600), 'wb') as file:
                    file.write(_data)
                if self._verbose:
                    print("DONE", file=sys.stderr)

            # Now do public key
            if _public_key:
                public_filename = private_filename + '.pub'
                if os.path.isfile(public_filename) and not overwrite:
                    if self._verbose:
                        self._print("File \"{}\" exists"
                                    .format(os.path.basename(public_filename)))
                    print("FAILED", file=sys.stderr)
                else:
                    cmd = ['ssh-keygen', '-y', '-f', private_filename]
                    rtn = self._ssh_askpass(cmd, public_keys[key_id]['uuid'])
                    if rtn.returncode == 0:
                        if self._verbose:
                            self._print("Writing public  key \"{}\""
                                        .format(
                                            os.path.basename(public_filename)))

                        with open(os.open(public_filename,
                                          os.O_CREAT | os.O_WRONLY,
                                          0o644), 'wb') as file:
                            file.write(rtn.stdout)
                        if self._verbose:
                            print("DONE", file=sys.stderr)
                    else:
                        print("Unable to generate public key for private key "
                              "\"{}\" ....".format(key_id), file=sys.stderr)
