# config.py
# Copyright (c) Ben Millwood 2009
# Copyright (c) Darren Salt 2012
# This file is part of the Tremulous Master server.
'''Configuration for the Tremulous Master

This module provides the MasterConfig class, and the ConfigError exception.
The latter is raised when the former fails to initialise for some reason.
The former, after its parse() method is called, provides the following
instance variables:

VERSION:
        a string giving the name and version of the master
CHALLENGE_LENGTH:
        the length of a getinfo challenge sent to servers
CHALLENGE_TIMEOUT:
        in seconds, the time a server has after being challenged to respond
SERVER_TIMEOUT:
        a server that has not sent a heartbeat in this period will be forgotten
GSR_MAXSERVERS:
        the maximum number of server addresses to be sent in a single
        getservers[Ext]Response packet (the client will only accept so many)
FEATURED_FILE, IGNORE_FILE, MOTD_FILE:
        These are mostly for internal use, but contain the file names from
        which the featured servers, address blacklist, and motd are read.
ipv4, ipv6:
        These variables specify which interfaces the client will use: at least
        one will be true, or ConfigError will be raised.
listen_addr, listen6_addr, port, challengeport:
        The master needs a socket for incoming connections, for each of IPv4
        and IPv6 that it is asked to use (currently it assumes the same port on
        each). These settings tell it to what address and port it should bind.
        It uses a separate port for outgoing challenges because some routers
        will redirect a 'response' to the heartbeat to the correct host even if
        they are not configured to do so for client requests. The separate port
        defeats this connection tracking and we only get a response if ports
        are set up correctly.
        inPort defaults to 30710; outPort defaults to inPort + 1
max_servers:
        This defaults to unlimited but if someone finds a way to flood the
        server list it could serve as a measure to prevent excessive RAM usage.
featured_servers:
        This is a dict of lists - each key is a label, and its value is a list
        of addresses. They will be sent in a separate response packet, headered
        with the label, so that the client can display them specially.

and some useful functions:

log(level, arg[, arg...], sep = ' '):
        level may be one of LOG_ERROR, LOG_PRINT, LOG_VERBOSE, or LOG_DEBUG:
        if the user's chosen verbosity level is less, the message will not be
        printed. All the subsequent arguments will be str()'d and printed,
        preceded by a timestamp and joined by the string given in the keyword
        argument `sep' (default ' ')
getmotd():
        Simply reads the motd file and returns the result.
ignore(addr):
        Reads the IGNORE_FILE and returns True if the given IP address string
        is blacklisted by its contents.
'''

# Required imports
from errno import ENOENT, EIO
from optparse import OptionParser, Values
from os import getenv
from sys import argv, exit, stdout
from time import strftime

# Local imports
from utils import inet_pton, valid_addr, stringtosockaddr

# Optional imports
# I named these variables in line with the standard library's has_ipv6.
# Surely that should be have_ipv6?
has_chroot, has_setuid, has_setgid, has_setgroups = True, True, True, True
try:
    from os import chdir, chroot
except ImportError:
    has_chroot = False
try:
    from pwd import getpwnam, getpwuid, getpwall
    from os import setuid, getuid
except ImportError:
    has_setuid = False
try:
    from os import setgid, getgid
except ImportError:
    has_setgid = False
try:
    from os import setgroups, getgroups
except ImportError:
    has_setgroups = False

# I don't have a non-IPv6 computer, so I'm not sure how this works
try:
    from socket import has_ipv6
except ImportError:
    has_ipv6 = False

( # Log levels
    LOG_ALWAYS,
    LOG_ERROR,
    LOG_PRINT,
    LOG_VERBOSE,
    LOG_DEBUG,
    LOG_LEVELS
) = list(range(6))
# and their names
loglevels = ['ALWAYS', 'ERROR', 'PRINT', 'VERBOSE', 'DEBUG']

def concat(*args, **kwargs):
    # docstring TODO
    try:
        sep = kwargs['sep']
        del kwargs['sep']
    except KeyError:
        sep = ' '

    if kwargs:
        raise TypeError('unexpected keyword arguments: ' +
                        str(list(kwargs.keys())))

    return sep.join(map(str, args))

class ConcatError(Exception):
    # docstring TODO
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, concat(*args, **kwargs))

class ConfigError(ConcatError):
    # docstring TODO
    pass

class MasterConfig(object):
    # docstring TODO
    def constants(self):
        '''Sets instance variables that do not change at run-time'''
        self.VERSION = 'Tremulous Master Server v0.1'

        # A getinfo request with a challenge longer than 128 chars will be
        # ignored. In practice this is far more than is necessary anyway.
        self.CHALLENGE_LENGTH = 12
        # This should be enough time for any decent connection but probably not
        # enough for a fast typist with netcat
        self.CHALLENGE_TIMEOUT = 5
        # Heartbeats are usually sent every ten minutes
        self.SERVER_TIMEOUT = 11 * 60
        # src/client/cl_main.c -- MAX_SERVERSPERPACKET
        # This limit should be hit long before the overall length limit of
        # 16384 bytes
        self.GSR_MAXSERVERS = 256

        self.IGNORE_FILE = 'ignore.txt'
        self.FEATURED_FILE = 'featured.txt'
        self.MOTD_FILE = 'motd.txt'

        # Plugin configuration - plugins disabled by default, must be explicitly enabled
        self.puppet_remote_master = None
        self.puppet_remote_port = 30710
        self.puppet_protocol = '71'  # Default protocol version
        self.puppet_use_websocket = False  # Use WebSocket instead of UDP
        self.puppet_interval = 300  # 5 minutes
        self.puppet_enabled = False
        self.puppet_run_once = False  # If True, only run sync once and exit (don't start background thread)
        self.sleepyteepee_enabled = False  # Sleepyteepee REST API plugin

    def __init__(self, vlevel = LOG_PRINT):
        # docstring TODO
        # Set this early so that self.log can be used immediately
        self.options = Values()
        self.options.verbose = vlevel

    def parse(self):
        # docstring TODO
        self.constants()
        self.cmdline()
        self.files()

    def __getattr__(self, attr):
        '''When the command line options have been parsed, this allows direct
        access to them'''
        # They aren't set as attributes of self directly because of the way
        # optparse.OptionParser works.
        return getattr(object.__getattribute__(self, 'options'), attr)

    def cmdline(self):
        '''Parse options from the command line. For an explanation of the
        options and their usage, use:

        python master.py --help
        '''
        # This is a m-m-m-monster function, but sometimes there are just lots
        # of things to do, and that is how it is.
        self.constants()
        # we add our own help option for obscure reasons
        parser = OptionParser(add_help_option = False)
        parser.add_option('-h', '--help', action = 'store_true',
                          help = 'Display this help and exit')
        # options other than --help are in loose alphabetical order
        parser.add_option('-4', '--ipv4', action = 'store_true',
                    default = True, dest = 'ipv4',
                    help = 'Use IPv4 (enabled by default)')
        if has_ipv6:
            parser.add_option('-6', '--ipv6', action = 'store_true',
                              default = False, dest = 'ipv6',
                              help = 'Enable IPv6 (disabled by default)')
        # a better error message here for invalid values would be nice
        parser.add_option('-d', '--db', help = 'Database backend to use, '
                          '<none|tdb|sqlite|auto>',
                          metavar = 'NAME', default = 'auto',
                          choices = ['none', 'tdb', 'sqlite', 'auto'])
        if has_chroot:
            parser.add_option('-j', '--jail',
                              help = 'Path to chroot into at startup',
                              metavar = 'DIR')
        parser.add_option('-l', '--listen-addr',
                          help = 'IPv4 address to listen to',
                          metavar = 'ADDR',
                          default = getenv('LISTEN_ADDR'))
        if has_ipv6:
            # Can we put this in the conditional above without spoiling
            # the ordering?
            parser.add_option('-L', '--listen6-addr',
                              help = 'IPv6 address to listen to (default: :: if --ipv6 is used)',
                              metavar = 'ADDR',
                              default = getenv('LISTEN6_ADDR'))
        parser.add_option('-n', '--max-servers', type = 'int',
                          help = 'Maximum number of servers to track',
                          metavar = 'NUM')
        parser.add_option('-p', '--port', action='append', type = 'int',
                          dest='ports', help = 'Port for incoming requests. '
                          'May be specified multiple times to listen on '
                          'additional ports.', metavar = 'NUM')
        parser.add_option('-P', '--challengeport', type = 'int',
                          help = 'Port for outgoing challenges',
                          metavar = 'NUM')
        parser.add_option('-q', action = 'count', default = 0,
                          help = 'Decrease verbose level. Multiple -q options '
                                 'may suppress logging entirely.')
        if has_setuid:
            parser.add_option('-u', '--user',
                              help = 'User to switch to at startup')
        parser.add_option('-v', action = 'count', default = 0,
                          help = 'Increase verbose level. Multiple -v options '
                                 'increase the level further.')
        parser.add_option('--verbose', type = 'int', default = LOG_PRINT,
                          help = 'Set verbose level directly. Takes a single '
                                 'integer argument between {0} and {1}'.format(
                                 LOG_ALWAYS, LOG_LEVELS - 1),
                          metavar = 'LEVEL')
        parser.add_option('-V', '--version', action = 'store_true',
                          help = 'Show version information')
        parser.add_option('-w', '--use_ws', action = 'store_true',
                    default = True, dest = 'use_ws',
                    help = 'Enable IPv4 WebSockets')
        parser.add_option('-W', '--ws_ports', action='append', type = 'int',
                           dest='ws_ports', help = 'Websocket ports for incoming requests. '
                             'May be specified multiple times to listen on '
                             'additional ports.', metavar = 'NUM')
        # SSL options from master branch
        parser.add_option('-s', '--use_ws_ssl', action = 'store_true',
                         default = True, dest = 'use_ws_ssl',
                         help = 'Enable SSL/TLS support over WebSockets')
        parser.add_option('-k', '--ws_ssl_key', type = 'str', dest = 'ws_ssl_key',
                            help = 'SSL Key for WebSockets')
        parser.add_option('-K', '--ws_ssl_cert', type = 'str', dest = 'ws_ssl_cert',
                            help = 'SSL Cert for WebSockets')
        # Plugin options from puppet branch
        parser.add_option('--puppet-master', help = 'Remote master server address for puppet plugin',
                            metavar = 'ADDR')
        parser.add_option('--puppet-port', type = 'int',
                            help = 'Remote master server port for puppet plugin',
                            metavar = 'PORT')
        parser.add_option('--puppet-protocol', help = 'Protocol version for puppet plugin (default: 71)',
                            metavar = 'PROTOCOL')
        parser.add_option('--puppet-use-websocket', action = 'store_true',
                            help = 'Use WebSocket instead of UDP for puppet plugin connections')
        parser.add_option('--puppet-interval', type = 'int',
                            help = 'Sync interval for puppet plugin (seconds)',
                            metavar = 'SECONDS')
        parser.add_option('--puppet-enable', action = 'store_true',
                            help = 'Enable the puppet plugin')
        parser.add_option('--puppet-run-once', action = 'store_true',
                            help = 'Run puppet sync once and exit (do not start background thread)')
        parser.add_option('--enable-sleepyteepee', action = 'store_true',
                            help = 'Enable the Sleepyteepee REST API plugin')
        # Also support environment variables for plugin enable flags
        if getenv('PUPPET_ENABLE', '').lower() in ('1', 'true', 'yes', 'on'):
            self.puppet_enabled = True
        if getenv('SLEEPYTEEPEE_ENABLE', '').lower() in ('1', 'true', 'yes', 'on'):
            self.sleepyteepee_enabled = True
        if getenv('PUPPET_PORT'):
            self.puppet_remote_port = int(getenv('PUPPET_PORT'))
        if getenv('PUPPET_INTERVAL'):
            self.puppet_interval = int(getenv('PUPPET_INTERVAL'))
        parser.add_option('--api-host', help='Host to bind REST API server', metavar='ADDR',
                            default = getenv('API_HOST'))
        parser.add_option('--api-port', type='int', help='Port for REST API server', metavar='PORT',
                            default = int(getenv('API_PORT')) if getenv('API_PORT') else None)
        parser.add_option('--api-port-from-env', type='int', help='Port for REST API server from env var API_PORT', metavar='PORT')
        parser.add_option('--api-keys', help='Comma-separated list of API keys', metavar='KEYS',
                            default = getenv('API_KEYS'))
        self.options, args = parser.parse_args(argv[1:])
        if args:
            raise ConfigError('Unexpected command line arguments')

        if self.help:
            stdout.write(parser.format_help())
            exit(0)
        # don't need this anymore
        parser.destroy()
        del parser

        if self.version:
            stdout.write('{0}\n'.format(self.VERSION))
            exit(0)

        self.verbose += self.v - self.q

        if not LOG_ALWAYS <= self.verbose < LOG_LEVELS:
            raise ConfigError('Verbose level must be between', LOG_ALWAYS,
                              'and', LOG_LEVELS - 1,
                              '(not {0})'.format(self.verbose))

        self.log(LOG_VERBOSE, 'Logging:', *loglevels[:self.verbose + 1])

        if not self.ipv4 and not self.ipv6:
            raise ConfigError('At least one of IPv4 or IPv6 must be enabled')

        # Set default IPv6 listen address if IPv6 is enabled but no address is specified
        if self.ipv6 and self.listen6_addr is None:
            self.listen6_addr = '::'
            self.log(LOG_VERBOSE, 'IPv6: No listen address specified, using default ::')

        if self.user is not None:
            try:
                pwnam = getpwnam(self.user)
                uid = pwnam.pw_uid
            except KeyError:
                try:
                    uid = int(self.user)
                    pwnam = getpwuid(uid)
                except ValueError:
                    raise ConfigError(self.user, 'no such user', sep = ': ')

            if has_setgid:
                gid = pwnam.pw_gid

        if self.jail is not None:
            try:
                chdir(self.jail)
                chroot('.')
            except OSError as err:
                raise ConfigError('chroot {0}:'.format(self.jail),
                                  err.strerror)
            self.log(LOG_VERBOSE, 'Chrooted to', self.jail)

        if self.user is not None:
            # okay, probably root at this point
            if has_setgroups:
                try:
                    setgroups(())
                except OSError as err:
                    raise ConfigError('setgroups:', err.strerror)

            if has_setgid:
                try:
                    setgid(gid)
                except OSError as err:
                    raise ConfigError('setgid {0}:'.format(gid), err.strerror)

            # setuid last, so setgroups & setgid don't fail
            try:
                setuid(uid)
            except OSError as err:
                raise ConfigError('setuid {0}:'.format(uid), err.strerror)

            pwnam = None

            self.log(LOG_VERBOSE, 'UID set to', getuid())

        if self.ports is None:
            self.ports = [30710]
        else:
            self.ports = sorted(set(self.ports))

        if self.challengeport is None:
            self.challengeport = self.ports[-1] + 1
            while self.challengeport > 0xffff or \
               self.challengeport in self.ports:
                self.challengeport = (self.challengeport & 0xffff) + 1
            self.log(LOG_VERBOSE, 'Automatically set challenge port to',
                                  self.challengeport)
        elif self.challengeport in self.ports:
            raise ConfigError('Challenge port cannot be the same as a request '
                              'port ({0})'.format(self.challengeport))

        # Set plugin configuration
        if self.puppet_master:
            self.puppet_remote_master = self.puppet_master
        if self.puppet_port:
            self.puppet_remote_port = self.puppet_port
        if self.options.puppet_protocol:
            self.puppet_protocol = self.options.puppet_protocol
        if self.options.puppet_use_websocket:
            self.puppet_use_websocket = self.options.puppet_use_websocket
        if self.puppet_interval:
            self.puppet_interval = self.puppet_interval
        if self.puppet_enable:
            self.puppet_enabled = True
        if self.options.puppet_run_once:
            self.puppet_run_once = True
        if self.options.enable_sleepyteepee:
            self.sleepyteepee_enabled = True
        if self.options.api_host is not None:
            self.api_host = self.options.api_host
        if self.options.api_port is not None:
            self.api_port = self.options.api_port
        if self.options.api_port_from_env is not None:
            self.api_port_from_env = self.options.api_port_from_env
        elif getenv('SLEEPYTEEPEE_PORT'):
            self.api_port_from_env = int(getenv('SLEEPYTEEPEE_PORT'))
        if self.options.api_keys is not None:
            self.api_keys = self.options.api_keys

    def files(self):
        '''Read self.FEATURED_FILE, and for each label (starting at column 0)
        construct a dict of the (indented) addresses following it. Each dict
        value starts off as None, to be initialised as the connections are
        made.
        self.featured_servers[label] is set to its corresponding dict.
        A missing file is ignored but other errors - e.g. if the file is
        present but can't be read - are fatal.'''
        self.featured_servers = dict()
        # FIXME: use ConfigError where appropriate
        try:
            with open(self.FEATURED_FILE) as featured:
                errmsg = self.FEATURED_FILE + ':'
                self.log(LOG_DEBUG, 'Opened', self.FEATURED_FILE)
                label = ''
                lineno = 0
                for line in iter(l.rstrip() for l in featured):
                    lineno += 1
                    wheremsg = '{0}:{1}:'.format(self.FEATURED_FILE, lineno)
                    # ignore blank lines and comments
                    if not line or line.isspace() or \
                       line.lstrip().startswith('#'):
                        continue
                    # indented lines are server addresses
                    if line[0].isspace():
                        addr = line.lstrip()
                        if not label:
                            raise ConfigError(errmsg, 'Error: missing label')
                        try:
                            saddr = stringtosockaddr(addr)
                        except EnvironmentError as err:
                            # EnvironmentError covers socket.error and
                            # .gaierror without having to import them
                            raise ConfigError(wheremsg, "Error: couldn't "
                                              'convert', addr,
                                              'to address format:', err)
                        if saddr in list(self.featured_servers[label].keys()):
                            self.log(LOG_PRINT, wheremsg, 'Warning:',
                                     saddr, 'appears multiple times')
                        self.featured_servers[label][saddr] = None
                    # unindented lines start a new label
                    else:
                        # clean up the old label
                        if label:
                            if not self.featured_servers[label]:
                                raise ConfigError(wheremsg, 'Error: no '
                                                  'addresses defined for',
                                                  label)
                            else:
                                # print a message of the form
                                # featured.txt: 'Label': [server1, server2,...]
                                self.log(LOG_VERBOSE, self.FEATURED_FILE,
                                         repr(label),
                                         list(self.featured_servers[label].keys()),
                                         sep = ': ')
                        label = line
                        for c in label:
                            # slashes are field seperators in
                            # getserversExtResponse
                            if c in '\\/':
                                raise ConfigError(wheremsg, 'Error:',
                                         'label', repr(label), 'contains '
                                         'invalid character:', c)
                        self.featured_servers[label] = dict()
                if label:
                    # print a message of the form
                    # featured.txt: 'Label': [server1, server2, ...]
                    self.log(LOG_VERBOSE, self.FEATURED_FILE, repr(label),
                             list(self.featured_servers[label].keys()), sep = ': ')
        except IOError as err:
            if err.errno != ENOENT:
                raise

    def getmotd(self):
        '''Reads the motd file and returns the contents'''
        # FIXME: validate the value as an info parameter (no \\ etc.)
        try:
            with open(self.MOTD_FILE) as motd:
                return motd.read().rstrip('\n')
        except IOError as err:
            if err.errno != ENOENT:
                raise

    def ignore(self, addr):
        '''Read self.IGNORE_FILE to check if addr (an IP) is in it.

        The file should consist of blank-separated addresses or address ranges
        in CIDR format to ignore.'''
        bits = inet_pton(valid_addr(addr), addr)
        try:
            with open(self.IGNORE_FILE) as ignore:
                for line in ignore:
                    # comments
                    if line.lstrip().startswith('#'):
                        continue
                    for word in line.split():
                        try:
                            # is this CIDR?
                            iaddr, mask = word.split('/', 1)
                            mask = int(mask)
                        except ValueError:
                            try:
                                # exact match only
                                if bits == inet_pton(valid_addr(word), word):
                                    return True
                            except EnvironmentError as err:
                                # inet_pton failed
                                self.log(LOG_PRINT, 'ignore.txt token', word,
                                         'could not be parsed:', err)
                            continue
                        try:
                            ibits = inet_pton(valid_addr(iaddr), iaddr)
                        except EnvironmentError:
                            continue
                        for byte, ibyte in zip(bits, ibits):
                            if not mask:
                                return True
                            elif mask >= 8:
                                if byte != ibyte:
                                    return False
                                mask -= 8
                            else:
                                b, i = ord(byte), ord(ibyte)
                                m = 0xff00 >> mask
                                return b & m == i & m

        except IOError as err:
            if err.errno != ENOENT:
                raise

    @staticmethod
    def logprefix(level):
        # docstring TODO
        # not sure why this is a separate method
        time = strftime('%H:%M:%S')
        levelname = loglevels[level]
        shortlevel = levelname[:3]
        return '[{time}] {levelname[0]} '.format(**locals())

    def log(self, level, *args, **kwargs):
        '''log(level, arg[, arg]*[, sep = ' '])

        If the configuration-specified verbosity is below level, nothing
        happens, otherwise a timestamp and then each str(arg) joined by the
        optional keyword argument sep (default space) is printed.

        IOError with errno EIO is ignored
        '''

        if not args:
            raise TypeError('MasterConfig.log() requires at least one '
                            'argument')
        if level > self.verbose:
            return

        argstr = concat(*args, **kwargs)

        try:
            stdout.write(self.logprefix(level) + argstr + '\n')
            stdout.flush()
        except IOError as err:
            if err.errno == EIO:
                pass
            else:
                raise

config = MasterConfig()
log = config.log
