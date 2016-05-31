#!/usr/bin/env python
"""Utility to answer 'Is my checked out copy up to date and in sync?'.

Git is very flexible and thus it ends up being not entirely trivial
to understand whether the checked out copy of a repository on a
running system is in sync with the expected branch/ref of a master
repository. This script is an attempt to make this check easy.
"""
import logging
import optparse
import re
import subprocess

__VERSION__ = '0.01'

# Options and arguments
p = optparse.OptionParser(description='Check code from git matches expected state',
                          usage='usage: %prog -r repo -l login -d dir [--ref ref] '
                                '(-h for help)',
                          version='%prog ' + __VERSION__)

p.add_option('--repo', '-r', action='store', default=None,
             help='git repo to check against')
p.add_option('--login', '-l', action='store', default=None,
             help='login [user@]host for machine to check [defaults to local check]')
p.add_option('--dir', '-d', action='store', default=None,
             help='directory where checked out copy exists')
p.add_option('--ref', action='store', default='refs/heads/master',
             help='ref to check against [default %default]')
p.add_option('--verbose', '-v', action='store_true',
             help='be verbose')

(opts, args) = p.parse_args()

level = logging.INFO if opts.verbose else logging.WARN
logging.basicConfig(level=level)

if (len(args) > 0):
    p.error("No arguments accepted (only options)")
if (opts.repo is None):
    p.error("Must specify git repository (--repo/-r)")
if (opts.dir is None):
    p.error("Must specify git directory to check (--dir/-d)")

# Sanity check the parameters
if (opts.repo and not re.match(r'''[[\w\-\.@:/]+$''', opts.repo)):
    p.error("Unsafe looking repo option, aborting.")
if (opts.login and not re.match(r'''[\w\-\.@]+$''', opts.login)):
    p.error("Unsafe looking login option, aborting.")
if (opts.dir and not re.match(r'''[\w/][\w\-\./]*$''', opts.dir)):
    p.error("Unsafe looking dir option, aborting.")
if (opts.ref and not re.match(r'''[\w\-/]+$''', opts.ref)):
    p.error("Unsafe looking ref option, aborting.")

# First, get hash for git repo
out = subprocess.check_output(['git','ls-remote',opts.repo,'-h',opts.ref])
out = out.decode('utf-8')
try:
    (repo_hash, repo_ref) = out.split()
except ValueError:
    raise Exception("Failed to extract hash for ref '%s' from response: '%s'" % (opts.ref, out))
logging.info("Repository: %s  %s" % (repo_hash, repo_ref))

# Second, get hash for checked out code in given dir
hash_cmd = 'cd %s; git rev-parse HEAD' % (opts.dir)
sync_cmd = 'cd %s; git status --porcelain -s' % (opts.dir)
if (opts.login is None):
    # Local
    copy_hash = subprocess.check_output(hash_cmd % (opts.dir), shell=True)
    copy_sync = subprocess.check_output(sync_cmd % (opts.dir), shell=True)
else:
    # Remote
    copy_hash = subprocess.check_output("ssh %s '%s'" % (opts.login, hash_cmd), shell=True) 
    copy_sync = subprocess.check_output("ssh %s '%s'" % (opts.login, sync_cmd), shell=True) 
copy_hash = copy_hash.decode('utf-8').rstrip()
copy_sync = copy_sync.decode('utf-8').rstrip()
logging.info("Copy:       %s" % (copy_hash))

# Finally, compare
if (repo_hash == copy_hash):
    print("OK")
else:
    print("Checked out copy does not match repository %s" % (opts.ref))
print(copy_sync)
