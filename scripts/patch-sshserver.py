#!/usr/bin/env python3
"""Patch curl's sshserver.pl to also generate ed25519 host keys.

russh 0.57.x has issues verifying RSA server signatures with some
OpenSSH versions. Adding an ed25519 host key lets russh negotiate
ed25519 instead, which works reliably.
"""

import sys

KEYGEN_PATCH = r'''
# urlx patch: generate ed25519 host key for russh compatibility
{
    my $hsted25519f = 'curl_host_ed25519_key';
    if(! -e pp($hsted25519f)) {
        logmsg "generating ed25519 host key...\n" if($verbose);
        system "\"$sshkeygen\" -q -t ed25519 -f " . pp($hsted25519f) . " -C 'curl test server ed25519' -N ''";
        chmod 0600, pp($hsted25519f);
    }
}
'''

HOSTKEY_PATCH = r'''
# urlx patch: add ed25519 host key for russh compatibility
{
    my $ed25519key = abs_path(pp('curl_host_ed25519_key'));
    if(-e $ed25519key) {
        push @cfgarr, "HostKey $ed25519key";
    }
}
'''

def patch(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    result = []
    for line in lines:
        result.append(line)
        # Place ed25519 key generation AFTER the RSA key generation block
        # (after the closing } of the if block that checks for existing keys)
        # The marker is: "Convert paths for curl's tests running on Windows"
        if "Convert paths for curl's tests running on Windows" in line:
            result.append(KEYGEN_PATCH)
        # After RSA HostKey config, add ed25519 HostKey
        if 'push @cfgarr, "HostKey $hstprvkeyf_config";' in line:
            result.append(HOSTKEY_PATCH)

    with open(path, 'w') as f:
        f.writelines(result)

if __name__ == '__main__':
    patch(sys.argv[1])
