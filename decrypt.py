#!/usr/bin/env python3
"""
Firefox Password Decryptor - Automatic Multi-Profile Version
Automatically processes all Firefox profiles and saves passwords to CSV
"""

import argparse
import csv
import ctypes as ct
import json
import logging
import os
import select
import sqlite3
import sys
from base64 import b64decode
from getpass import getpass
from subprocess import PIPE, Popen

try:
    # Python 3
    from subprocess import DEVNULL
except ImportError:
    # Python 2
    DEVNULL = open(os.devnull, 'w')

try:
    # Python 3
    from urllib.parse import urlparse
except ImportError:
    # Python 2
    from urlparse import urlparse

try:
    # Python 3
    from configparser import ConfigParser
    raw_input = input
except ImportError:
    # Python 2
    from ConfigParser import ConfigParser

PY3 = sys.version_info.major > 2
LOG = None
VERBOSE = False
SYS64 = sys.maxsize > 2**32

if not PY3 and os.name == "nt":
    sys.stderr.write("WARNING: You are using Python 2 on Windows. If your "
                     "passwords include non-alphanumeric characters you "
                     "will run into problems.\n")
    sys.stderr.write("WARNING: Python 2 + Windows is no longer supported. "
                     "Please use Python 3 instead\n")

# Windows uses a mixture of different codecs for different components
# ANSI CP1252 for system messages, while NSS uses UTF-8
# To further complicate things, with python 2.7 the default stdout/stdin codec
# isn't UTF-8 but language dependent (tested on Windows 7)

if os.name == "nt":
    SYS_ENCODING = "cp1252"
    LIB_ENCODING = "utf8"
else:
    SYS_ENCODING = "utf8"
    LIB_ENCODING = "utf8"

# When using pipes stdin/stdout encoding may be None
USR_ENCODING = sys.stdin.encoding or sys.stdout.encoding or "utf8"


def py2_decode(_bytes, encoding=USR_ENCODING):
    if PY3:
        return _bytes
    else:
        return _bytes.decode(encoding)


def py2_encode(_unicode, encoding=USR_ENCODING):
    if PY3:
        return _unicode
    else:
        return _unicode.encode(encoding)


def type_decode(encoding):
    return lambda x: py2_decode(x, encoding)


def get_version():
    """Obtain version information from git if available otherwise use
    the internal version number
    """
    def internal_version():
        return '.'.join(map(str, __version_info__[:3])) + ''.join(__version_info__[3:])

    try:
        p = Popen(["git", "describe", "--tags"], stdout=PIPE, stderr=DEVNULL)
    except OSError:
        return internal_version()

    stdout, stderr = p.communicate()

    if p.returncode:
        return internal_version()
    else:
        # Both py2 and py3 return bytes here
        return stdout.decode(USR_ENCODING).strip()


__version_info__ = (0, 8, 0, "+git")
__version__ = get_version()


class NotFoundError(Exception):
    """Exception to handle situations where a credentials file is not found
    """
    pass


class Exit(Exception):
    """Exception to allow a clean exit from any point in execution
    """
    ERROR = 1
    MISSING_PROFILEINI = 2
    MISSING_SECRETS = 3
    BAD_PROFILEINI = 4
    LOCATION_NO_DIRECTORY = 5
    BAD_SECRETS = 6

    FAIL_LOCATE_NSS = 10
    FAIL_LOAD_NSS = 11
    FAIL_INIT_NSS = 12
    FAIL_NSS_KEYSLOT = 13
    FAIL_SHUTDOWN_NSS = 14
    BAD_MASTER_PASSWORD = 15
    NEED_MASTER_PASSWORD = 16

    PASSSTORE_NOT_INIT = 20
    PASSSTORE_MISSING = 21
    PASSSTORE_ERROR = 22

    READ_GOT_EOF = 30
    MISSING_CHOICE = 31
    NO_SUCH_PROFILE = 32

    UNKNOWN_ERROR = 100
    KEYBOARD_INTERRUPT = 102

    def __init__(self, exitcode):
        self.exitcode = exitcode

    def __unicode__(self):
        return "Premature program exit with exit code {0}".format(self.exitcode)


class Credentials(object):
    """Base credentials backend manager
    """
    def __init__(self, db):
        self.db = db

        LOG.debug("Database location: %s", self.db)
        if not os.path.isfile(db):
            raise NotFoundError("ERROR - {0} database not found\n".format(db))

        LOG.info("Using %s for credentials.", db)

    def __iter__(self):
        pass

    def done(self):
        """Override this method if the credentials subclass needs to do any
        action after interaction
        """
        pass


class SqliteCredentials(Credentials):
    """SQLite credentials backend manager
    """
    def __init__(self, profile):
        db = os.path.join(profile, "signons.sqlite")

        super(SqliteCredentials, self).__init__(db)

        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self):
        LOG.debug("Reading password database in SQLite format")
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType "
                       "FROM moz_logins")
        for i in self.c:
            # yields hostname, encryptedUsername, encryptedPassword, encType
            yield i

    def done(self):
        """Close the sqlite cursor and database connection
        """
        super(SqliteCredentials, self).done()

        self.c.close()
        self.conn.close()


class JsonCredentials(Credentials):
    """JSON credentials backend manager
    """
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")

        super(JsonCredentials, self).__init__(db)

    def __iter__(self):
        with open(self.db) as fh:
            LOG.debug("Reading password database in JSON format")
            data = json.load(fh)

            try:
                logins = data["logins"]
            except Exception:
                LOG.error("Unrecognized format in {0}".format(self.db))
                raise Exit(Exit.BAD_SECRETS)

            for i in logins:
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])


class NSSDecoder(object):
    class SECItem(ct.Structure):
        """struct needed to interact with libnss
        """
        _fields_ = [
            ('type', ct.c_uint),
            ('data', ct.c_char_p),  # actually: unsigned char *
            ('len', ct.c_uint),
        ]

    class PK11SlotInfo(ct.Structure):
        """opaque structure representing a logical PKCS slot
        """

    def __init__(self):
        # Locate libnss and try loading it
        self.NSS = None
        self.load_libnss()

        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self._set_ctypes(ct.c_int, "NSS_Init", ct.c_char_p)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, ct.c_char_p)
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

        # for error handling
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _set_ctypes(self, restype, name, *argtypes):
        """Set input/output types on libnss C functions for automatic type casting
        """
        res = getattr(self.NSS, name)
        res.restype = restype
        res.argtypes = argtypes
        setattr(self, "_" + name, res)

    @staticmethod
    def find_nss(locations, nssname):
        """Locate nss is one of the many possible locations
        """
        fail_errors = []

        for loc in locations:
            nsslib = os.path.join(loc, nssname)
            LOG.debug("Loading NSS library from %s", nsslib)

            if os.name == "nt":
                # On windows in order to find DLLs referenced by nss3.dll
                # we need to have those locations on PATH
                os.environ["PATH"] = ';'.join([loc, os.environ["PATH"]])
                LOG.debug("PATH is now %s", os.environ["PATH"])
                # However this doesn't seem to work on all setups and needs to be
                # set before starting python so as a workaround we chdir to
                # Firefox's nss3.dll location
                if loc:
                    if not os.path.isdir(loc):
                        # No point in trying to load from paths that don't exist
                        continue

                    workdir = os.getcwd()
                    os.chdir(loc)

            try:
                nss = ct.CDLL(nsslib)
            except OSError as e:
                fail_errors.append((nsslib, str(e)))
            else:
                LOG.debug("Loaded NSS library from %s", nsslib)
                return nss
            finally:
                if os.name == "nt" and loc:
                    # Restore workdir changed above
                    os.chdir(workdir)

        else:
            LOG.error("Couldn't find or load '%s'. This library is essential "
                      "to interact with your Mozilla profile.", nssname)
            LOG.error("If you are seeing this error please perform a system-wide "
                      "search for '%s' and file a bug report indicating any "
                      "location found. Thanks!", nssname)
            LOG.error("Alternatively you can try launching firefox_decrypt "
                      "from the location where you found '%s'. "
                      "That is 'cd' or 'chdir' to that location and run "
                      "firefox_decrypt from there.", nssname)

            LOG.error("Please also include the following on any bug report. "
                      "Errors seen while searching/loading NSS:")

            for target, error in fail_errors:
                LOG.error("Error when loading %s was %s", target, py2_decode(str(error), SYS_ENCODING))

            raise Exit(Exit.FAIL_LOCATE_NSS)

    def load_libnss(self):
        """Load libnss into python using the CDLL interface
        """
        if os.name == "nt":
            nssname = "nss3.dll"
            if SYS64:
                locations = (
                    "",  # Current directory or system lib finder
                    r"C:\Program Files\Mozilla Firefox",
                    r"C:\Program Files\Mozilla Thunderbird",
                    r"C:\Program Files\Nightly",
                )
            else:
                locations = (
                    "",  # Current directory or system lib finder
                    r"C:\Program Files (x86)\Mozilla Firefox",
                    r"C:\Program Files (x86)\Mozilla Thunderbird",
                    r"C:\Program Files (x86)\Nightly",
                    # On windows 32bit these folders can also be 32bit
                    r"C:\Program Files\Mozilla Firefox",
                    r"C:\Program Files\Mozilla Thunderbird",
                    r"C:\Program Files\Nightly",
                )

        elif os.uname()[0] == "Darwin":
            nssname = "libnss3.dylib"
            locations = (
                "",  # Current directory or system lib finder
                "/usr/local/lib/nss",
                "/usr/local/lib",
                "/opt/local/lib/nss",
                "/sw/lib/firefox",
                "/sw/lib/mozilla",
                "/usr/local/opt/nss/lib",  # nss installed with Brew on Darwin
                "/opt/pkg/lib/nss",  # installed via pkgsrc
            )

        else:
            nssname = "libnss3.so"
            if SYS64:
                locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )
            else:
                locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/lib32",
                    "/usr/lib32/nss",
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )

        # If this succeeds libnss was loaded
        self.NSS = self.find_nss(locations, nssname)

    def handle_error(self):
        """If an error happens in libnss, handle it and print some debug information
        """
        LOG.debug("Error during a call to NSS library, trying to obtain error info")

        code = self._PORT_GetError()
        name = self._PR_ErrorToName(code)
        name = "NULL" if name is None else name.decode(SYS_ENCODING)
        # 0 is the default language (localization related)
        text = self._PR_ErrorToString(code, 0)
        text = text.decode(SYS_ENCODING)

        LOG.debug("%s: %s", name, text)

    def decode(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)

        e = self._PK11SDR_Decrypt(inp, out, None)
        LOG.debug("Decryption of data returned %s", e)
        try:
            if e == -1:
                LOG.error("Password decryption failed. Passwords protected by a Master Password!")
                self.handle_error()
                raise Exit(Exit.NEED_MASTER_PASSWORD)

            res = ct.string_at(out.data, out.len).decode(LIB_ENCODING)
        finally:
            # Avoid leaking SECItem
            self._SECITEM_ZfreeItem(out, 0)

        return res


class NSSInteraction(object):
    """
    Interact with lib NSS
    """
    def __init__(self):
        self.profile = None
        self.NSS = NSSDecoder()

    def load_profile(self, profile):
        """Initialize the NSS library and profile
        """
        # Normalize the path for Windows
        profile = os.path.normpath(profile)
        
        LOG.debug("Initializing NSS with profile path '%s'", profile)
        
        # Verify profile exists
        if not os.path.isdir(profile):
            LOG.error("Profile directory does not exist: %s", profile)
            raise Exit(Exit.FAIL_INIT_NSS)
            
        self.profile = profile

        # Convert to bytes for NSS
        profile_bytes = profile.encode(LIB_ENCODING)
        
        # Use proper NSS path format
        nss_path = b"sql:" + profile_bytes
        LOG.debug("NSS init path: %s", nss_path)

        e = self.NSS._NSS_Init(nss_path)
        LOG.debug("Initializing NSS returned %s", e)

        if e != 0:
            LOG.error("Couldn't initialize NSS for profile: %s", self.profile)
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_INIT_NSS)
    
    def attack(self, dictionary):
        """Dictionary attack
        """
        with open(dictionary) as f:
            for l in f:
                password = l.strip()
                if password == "" or password.startswith("#"):
                    continue
                try:
                    self.authenticate(False, password, True)
                    LOG.info("Password found: {}".format(password))
                    break
                except Exit:
                    continue
        self.authenticate(False, password)

    def authenticate(self, interactive, password=None, silent=False):
        """Check if the current profile is protected by a master password,
        prompt the user and unlock the profile.
        """
        if not silent:
            LOG.debug("Retrieving internal key slot")
        keyslot = self.NSS._PK11_GetInternalKeySlot()

        if not silent:
            LOG.debug("Internal key slot %s", keyslot)
        if not keyslot:
            LOG.error("Failed to retrieve internal KeySlot")
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_NSS_KEYSLOT)
        
        # ALWAYS use empty password, NEVER prompt
        password = ""
        try:
            if password:
                LOG.debug("Authenticating with password '%s'", password)
                e = self.NSS._PK11_CheckUserPassword(keyslot, password.encode(LIB_ENCODING))
                
                if not silent:
                    LOG.debug("Checking user password returned %s", e)

                if e != 0:
                    if not silent:
                        LOG.error("Master password is not correct")

                    self.NSS.handle_error()
                    raise Exit(Exit.BAD_MASTER_PASSWORD)

            else:
                LOG.warning("Attempting decryption with no Master Password")
        finally:
            # Avoid leaking PK11KeySlot
            self.NSS._PK11_FreeSlot(keyslot)

    def unload_profile(self):
        """Shutdown NSS and deactivate current profile
        """
        e = self.NSS._NSS_Shutdown()

        if e != 0:
            LOG.error("Couldn't shutdown current NSS profile")

            self.NSS.handle_error()
            raise Exit(Exit.FAIL_SHUTDOWN_NSS)

    def decode_entry(self, user64, passw64):
        """Decrypt one entry in the database
        """
        LOG.debug("Decrypting username data '%s'", user64)
        user = self.NSS.decode(user64)

        LOG.debug("Decrypting password data '%s'", passw64)
        passw = self.NSS.decode(passw64)

        return user, passw

    def decrypt_passwords(self, output_file=None, csv_delimiter=",", csv_quotechar='"'):
        """
        Decrypt requested profile and save passwords to CSV file
        """
        credentials = obtain_credentials(self.profile)

        LOG.info("Decrypting credentials for profile: %s", self.profile)
        all_passwords = []
        profile_name = os.path.basename(self.profile)

        csv_file = None
        csv_writer = None
        
        if output_file:
            csv_file = open(output_file, 'a', newline='', encoding='utf-8')
            csv_writer = csv.DictWriter(
                csv_file, fieldnames=["profile", "url", "user", "password"],
                lineterminator="\n", delimiter=csv_delimiter,
                quotechar=csv_quotechar, quoting=csv.QUOTE_ALL,
            )
            # Write header only if file is empty
            if csv_file.tell() == 0:
                csv_writer.writeheader()

        for url, user, passw, enctype in credentials:
            if enctype:
                try:
                    user, passw = self.decode_entry(user, passw)
                except Exit as e:
                    if e.exitcode == Exit.NEED_MASTER_PASSWORD:
                        LOG.warning("Skipping profile %s - Master Password required", profile_name)
                        break
                    else:
                        raise

            LOG.debug("Decoded credentials for %s: %s / %s", url, user, passw)

            password_entry = {
                "profile": profile_name,
                "url": url,
                "user": user,
                "password": passw
            }
            all_passwords.append(password_entry)

            if csv_writer:
                csv_writer.writerow(password_entry)

        credentials.done()

        if csv_file:
            csv_file.close()

        if not all_passwords:
            LOG.warning("No passwords found in profile: %s", profile_name)
        else:
            LOG.info("Found %d passwords in profile: %s", len(all_passwords), profile_name)

        return all_passwords


def obtain_credentials(profile):
    """Figure out which of the 2 possible backend credential engines is available
    """
    try:
        credentials = JsonCredentials(profile)
    except NotFoundError:
        try:
            credentials = SqliteCredentials(profile)
        except NotFoundError:
            LOG.error("Couldn't find credentials file (logins.json or signons.sqlite).")
            raise Exit(Exit.MISSING_SECRETS)

    return credentials


def get_all_profiles(basepath):
    """Get all Firefox profiles from profiles.ini
    """
    profileini = os.path.join(basepath, "profiles.ini")

    if not os.path.isfile(profileini):
        LOG.warning("profiles.ini not found in %s", basepath)
        return []

    profiles = ConfigParser()
    profiles.read(profileini)

    all_profiles = []
    for section in profiles.sections():
        if section.startswith("Profile"):
            path = profiles.get(section, "Path")
            if profiles.has_option(section, "IsRelative") and profiles.get(section, "IsRelative") == "1":
                full_path = os.path.join(basepath, path)
            else:
                full_path = path
            
            # Normalize path for Windows - this converts / to \ and fixes path issues
            full_path = os.path.normpath(full_path)
            all_profiles.append(full_path)

    return all_profiles


def ask_password(profile, interactive):
    """
    Prompt for profile password - MODIFIED TO ALWAYS RETURN EMPTY STRING
    """
    # ALWAYS return empty string, never prompt
    return ""


def process_all_profiles(basepath, output_file, interactive=True, wordlist=None):
    """
    Process all Firefox profiles automatically - NO PASSWORD PROMPTS
    """
    nss = NSSInteraction()
    
    # Normalize basepath
    basepath = os.path.normpath(basepath)
    
    all_profiles = get_all_profiles(basepath)
    
    if not all_profiles:
        LOG.error("No profiles found in %s", basepath)
        # Try to use basepath as a profile directory
        if os.path.isdir(basepath):
            LOG.info("Trying basepath as profile: %s", basepath)
            all_profiles = [basepath]
        else:
            LOG.error("Basepath is not a valid directory: %s", basepath)
            return

    LOG.info("Found %d profiles to process", len(all_profiles))
    
    total_passwords = 0
    successful_profiles = 0

    for profile_path in all_profiles:
        profile_name = os.path.basename(profile_path)
        LOG.info("Processing profile: %s", profile_path)  # Log full path for debugging
        
        # Skip if profile directory doesn't exist
        if not os.path.isdir(profile_path):
            LOG.warning("Profile directory does not exist, skipping: %s", profile_path)
            continue
            
        try:
            # Start NSS for selected profile
            nss.load_profile(profile_path)
            
            # ALWAYS use empty password, NEVER prompt for passwords
            try:
                if wordlist:
                    nss.attack(wordlist)
                else:
                    # Force non-interactive with empty password - NO PROMPTS
                    nss.authenticate(False, "")
            except Exit as e:
                # Skip profile if empty password doesn't work - NO RETRY WITH PROMPT
                if e.exitcode in [Exit.BAD_MASTER_PASSWORD, Exit.NEED_MASTER_PASSWORD]:
                    LOG.warning("Skipping profile %s - Master Password required", profile_name)
                else:
                    LOG.warning("Skipping profile %s - Authentication failed (code: %s)", profile_name, e.exitcode)
                try:
                    nss.unload_profile()
                except:
                    pass
                continue

            # Decrypt passwords and save to CSV
            passwords = nss.decrypt_passwords(output_file=output_file)
            total_passwords += len(passwords)
            successful_profiles += 1
            
            # Shutdown NSS for this profile
            nss.unload_profile()
            
        except Exit as e:
            LOG.error("Error processing profile %s: %s", profile_name, e.exitcode)
            try:
                nss.unload_profile()
            except:
                pass
            continue
        except Exception as e:
            LOG.error("Unexpected error processing profile %s: %s", profile_name, str(e))
            try:
                nss.unload_profile()
            except:
                pass
            continue

    LOG.info("Successfully processed %d out of %d profiles", successful_profiles, len(all_profiles))
    LOG.info("Total passwords extracted: %d", total_passwords)
    if successful_profiles > 0:
        LOG.info("Passwords saved to: %s", output_file)
    else:
        LOG.error("No profiles were successfully processed!")


def parse_sys_args():
    """Parse command line arguments
    """

    if os.name == "nt":
        profile_path = os.path.join(os.environ['APPDATA'], "Mozilla", "Firefox")
    elif os.uname()[0] == "Darwin":
        profile_path = "~/Library/Application Support/Firefox"
    else:
        profile_path = "~/.mozilla/firefox"

    parser = argparse.ArgumentParser(
        description="Automatically decrypt all Firefox profiles and save passwords to CSV"
    )
    parser.add_argument("profile", nargs="?", default=profile_path,
                        type=type_decode(SYS_ENCODING),
                        help="Path to Firefox profile folder (default: {0})".format(profile_path))
    parser.add_argument("-o", "--output", default="firefox_passwords.csv",
                        help="Output CSV file (default: firefox_passwords.csv)")
    parser.add_argument("-d", "--delimiter", default=",",
                        help="CSV delimiter (default: ,)")
    parser.add_argument("-q", "--quotechar", default='"',
                        help="CSV quote character (default: \")")
    parser.add_argument("-n", "--no-interactive", dest="interactive",
                        default=True, action="store_false",
                        help="Disable interactivity (will skip password-protected profiles)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity level")
    parser.add_argument("--version", action="version", version=__version__,
                        help="Display version and exit")
    parser.add_argument("-w", "--wordlist", help="Wordlist for password guessing attack")

    args = parser.parse_args()

    return args


def setup_logging(args):
    """Setup the logging level and configure the basic logger
    """
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
    )

    global LOG
    LOG = logging.getLogger(__name__)


def main():
    """Main entry point
    """
    args = parse_sys_args()

    setup_logging(args)

    LOG.info("Running firefox_decrypt version: %s", __version__)
    LOG.debug("Parsed commandline arguments: %s", args)

    basepath = os.path.expanduser(args.profile)
    # Normalize the basepath for Windows
    basepath = os.path.normpath(basepath)
    
    LOG.info("Using Firefox directory: %s", basepath)

    # Process all profiles automatically - FORCE NON-INTERACTIVE
    process_all_profiles(
        basepath=basepath,
        output_file=args.output,
        interactive=False,  # Force non-interactive
        wordlist=args.wordlist
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print("Quit.")
        sys.exit(Exit.KEYBOARD_INTERRUPT)
    except Exit as e:
        sys.exit(e.exitcode)