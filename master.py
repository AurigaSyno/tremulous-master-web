#!/usr/bin/env python
###############################################################################
# master.py - a master server for Tremulous
# Copyright (c) 2009-2011 Ben Millwood
# Copyright (c) 2015 Jeff Kent
#
# Thanks to Mathieu Olivier, who wrote much of the original master in C
# (this project shares none of his code, but used it as a reference)
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
###############################################################################
"""The Tremulous Master Server
Requires Python 3

Protocol for this is pretty simple.
Accepted incoming messages:
    'heartbeat <game>\\n'
        <game> is ignored for the time being (it's always Tremulous in any
        case). It's a request from a server for the master to start tracking it
        and reporting it to clients. Usually the master will verify the server
        before accepting it into the server list.
    'getservers <protocol> [empty] [full]'
        A request from the client to send the list of servers.
""" # docstring TODO

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not available, continue without .env support

# Required imports
from errno import EINTR, ENOENT
from itertools import chain
from os import kill, getpid
from random import choice
from select import select, error as selecterror
from signal import signal, SIGINT, SIG_DFL
from socket import (socket, error as sockerr, has_ipv6,
                   AF_UNSPEC, AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, IPPROTO_UDP, IPPROTO_TCP)
from sys import exit, stderr
from time import time

from wsproto import ConnectionType, WSConnection
from wsproto.events import (AcceptConnection, CloseConnection, BytesMessage,
                            Ping, Pong, Request)

# Plugin system imports
try:
    from stevedore import extension
    PLUGINS_AVAILABLE = True
except ImportError:
    PLUGINS_AVAILABLE = False

# Local imports
from config import config, ConfigError
from config import log, LOG_ERROR, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG
from db import dbconnect
# inet_pton isn't defined on windows, so use our own
from utils import inet_pton, stringtosockaddr, valid_addr

try:
    config.parse()
except ConfigError as err:
    # Note that we don't know how much user config is loaded at this stage
    log(LOG_ERROR, err)
    exit(1)

try:
    log_client, log_gamestat, db_id = dbconnect(config.db)
except ImportError as ex:
    def nodb(*args):
        '''This function is defined and used when the database import fails'''
        log(LOG_DEBUG, 'No database, not logged:', args)
    log_client = log_gamestat = nodb
    log(LOG_PRINT, 'Warning: database not available')
else:
    log(LOG_VERBOSE, db_id)

# Optional imports
try:
    from signal import signal, SIGHUP, SIG_IGN
except ImportError:
    pass
else:
    signal(SIGHUP, SIG_IGN)

inSocks = list()

# dict: socks[address_family].family == address_family
outSocks = dict()

usingWs = False
ws_connections = dict()

# dict of [label][addr] -> Server instance
servers = dict((label, dict()) for label in
               chain(list(config.featured_servers.keys()), [None]))

# Plugin system
plugin_manager = None
loaded_plugins = []

def pre_initialize_plugins():
    """Pre-initialize plugins before socket binding.

    This allows plugins like the puppet plugin to fetch data from remote sources
    before the master server binds its ports.
    """
    global plugin_manager, loaded_plugins

    if not PLUGINS_AVAILABLE:
        log(LOG_PRINT, 'Warning: stevedore not available, plugin system disabled')
        return

    try:
        log(LOG_VERBOSE, 'Plugin system: Pre-initializing plugins...')
        log(LOG_DEBUG, 'Plugin system: Searching namespace: tremulous.master.plugins')

        plugin_manager = extension.ExtensionManager(
            namespace='tremulous.master.plugins',
            invoke_on_load=False,
        )

        extensions = list(plugin_manager.extensions)
        log(LOG_VERBOSE, 'Plugin system: Found {0} plugin extensions'.format(len(extensions)))

        for ext in extensions:
            try:
                log(LOG_DEBUG, 'Plugin system: Loading extension: {0}'.format(ext.name))
                log(LOG_DEBUG, 'Plugin system: Entry point: {0}'.format(ext.entry_point))

                # Check if plugin is enabled (plugins disabled by default)
                plugin_enabled = False
                if ext.name == 'puppet' and config.puppet_enabled:
                    plugin_enabled = True
                    log(LOG_VERBOSE, 'Plugin system: Puppet plugin enabled via --puppet-enable')
                elif ext.name == 'sleepyteepee' and config.sleepyteepee_enabled:
                    plugin_enabled = True
                    log(LOG_VERBOSE, 'Plugin system: Sleepyteepee plugin enabled via --enable-sleepyteepee')
                
                if not plugin_enabled:
                    log(LOG_VERBOSE, 'Plugin system: Plugin {0} is disabled (use --enable-{1} to enable)'.format(ext.name, ext.name))
                    continue

                # Load plugin class from entry point
                plugin_class = ext.entry_point.load()
                log(LOG_DEBUG, 'Plugin system: Loaded plugin class: {0}'.format(plugin_class.__name__))

                # Create plugin instance
                log(LOG_DEBUG, 'Plugin system: Creating plugin instance for {0}'.format(ext.name))
                plugin = plugin_class(config, servers, outSocks)

                # Call pre_initialize if available
                if hasattr(plugin, 'pre_initialize'):
                    log(LOG_DEBUG, 'Plugin system: Plugin {0} has pre_initialize method'.format(ext.name))
                    log(LOG_DEBUG, 'Plugin system: Pre-initializing plugin {0}...'.format(ext.name))
                    if plugin.pre_initialize():
                        loaded_plugins.append(plugin)
                        info = plugin.get_info()
                        log(LOG_PRINT, 'Plugin system: Pre-initialized plugin: {0} v{1} - {2}'.format(
                            info['name'], info['version'], info['description']))
                    else:
                        log(LOG_VERBOSE, 'Plugin system: Plugin {0} pre-initialization failed'.format(ext.name))
                else:
                    log(LOG_DEBUG, 'Plugin system: Plugin {0} does NOT have pre_initialize method'.format(ext.name))
                    # If plugin doesn't have pre_initialize, just add it for later initialization
                    loaded_plugins.append(plugin)
                    info = plugin.get_info()
                    log(LOG_DEBUG, 'Plugin system: Loaded plugin {0} (no pre-initialization)'.format(ext.name))
            except Exception as e:
                import traceback
                log(LOG_ERROR, 'Plugin system: Error loading plugin {0}: {1}'.format(ext.name, e))
                log(LOG_DEBUG, 'Plugin system: Traceback: {0}'.format(traceback.format_exc()))

        log(LOG_VERBOSE, 'Plugin system: Successfully pre-initialized {0} plugins'.format(len(loaded_plugins)))

    except Exception as e:
        import traceback
        log(LOG_ERROR, 'Plugin system: Error pre-initializing plugin system: {0}'.format(e))
        log(LOG_DEBUG, 'Plugin system: Traceback: {0}'.format(traceback.format_exc()))

def initialize_plugins():
    """Initialize and load all available plugins.

    This is called after socket binding to complete plugin initialization.
    Plugins that were pre-initialized will have their initialize() method called.
    """
    global plugin_manager, loaded_plugins

    if not PLUGINS_AVAILABLE:
        log(LOG_PRINT, 'Warning: stevedore not available, plugin system disabled')
        return

    if not plugin_manager:
        # If pre_initialize_plugins wasn't called, do full initialization
        try:
            log(LOG_VERBOSE, 'Plugin system: Initializing plugin discovery...')
            log(LOG_DEBUG, 'Plugin system: Searching namespace: tremulous.master.plugins')
            log(LOG_DEBUG, 'Plugin system: plugin_manager is None, pre_initialize_plugins() was not called or failed')

            plugin_manager = extension.ExtensionManager(
                namespace='tremulous.master.plugins',
                invoke_on_load=False,
            )

            extensions = list(plugin_manager.extensions)
            log(LOG_VERBOSE, 'Plugin system: Found {0} plugin extensions'.format(len(extensions)))

            for ext in extensions:
                try:
                    log(LOG_DEBUG, 'Plugin system: Loading extension: {0}'.format(ext.name))
                    log(LOG_DEBUG, 'Plugin system: Entry point: {0}'.format(ext.entry_point))

                    # Check if plugin is enabled (plugins disabled by default)
                    plugin_enabled = False
                    if ext.name == 'puppet' and config.puppet_enabled:
                        plugin_enabled = True
                        log(LOG_VERBOSE, 'Plugin system: Puppet plugin enabled via --puppet-enable')
                    elif ext.name == 'sleepyteepee' and config.sleepyteepee_enabled:
                        plugin_enabled = True
                        log(LOG_VERBOSE, 'Plugin system: Sleepyteepee plugin enabled via --enable-sleepyteepee')
                    
                    if not plugin_enabled:
                        log(LOG_VERBOSE, 'Plugin system: Plugin {0} is disabled (use --enable-{1} to enable)'.format(ext.name, ext.name))
                        continue

                    # Load plugin class from entry point
                    plugin_class = ext.entry_point.load()
                    log(LOG_DEBUG, 'Plugin system: Loaded plugin class: {0}'.format(plugin_class.__name__))

                    # Create plugin instance
                    log(LOG_DEBUG, 'Plugin system: Creating plugin instance for {0}'.format(ext.name))
                    plugin = plugin_class(config, servers, outSocks)

                    log(LOG_DEBUG, 'Plugin system: Initializing plugin {0}...'.format(ext.name))
                    if plugin.initialize():
                        loaded_plugins.append(plugin)
                        info = plugin.get_info()
                        log(LOG_PRINT, 'Plugin system: Loaded plugin: {0} v{1} - {2}'.format(
                            info['name'], info['version'], info['description']))
                    else:
                        log(LOG_VERBOSE, 'Plugin system: Plugin {0} initialization failed'.format(ext.name))
                except Exception as e:
                    log(LOG_ERROR, 'Plugin system: Error loading plugin {0}: {1}'.format(ext.name, e))

            log(LOG_VERBOSE, 'Plugin system: Successfully loaded {0} plugins'.format(len(loaded_plugins)))

        except Exception as e:
            log(LOG_ERROR, 'Plugin system: Error initializing plugin system: {0}'.format(e))
    else:
        # Plugins were pre-initialized, now call initialize() on each
        log(LOG_VERBOSE, 'Plugin system: Completing initialization for {0} pre-initialized plugins'.format(len(loaded_plugins)))
        for plugin in loaded_plugins:
            try:
                log(LOG_DEBUG, 'Plugin system: Initializing plugin {0}...'.format(plugin.get_name()))
                if plugin.initialize():
                    info = plugin.get_info()
                    log(LOG_PRINT, 'Plugin system: Initialized plugin: {0} v{1} - {2}'.format(
                        info['name'], info['version'], info['description']))
                else:
                    log(LOG_VERBOSE, 'Plugin system: Plugin {0} initialization failed'.format(plugin.get_name()))
            except Exception as e:
                log(LOG_ERROR, 'Plugin system: Error initializing plugin {0}: {1}'.format(plugin.get_name(), e))

def call_plugins_hook(hook_name, *args, **kwargs):
    """Call a hook on all loaded plugins."""
    log(LOG_DEBUG, 'Plugin system: Calling hook {0} on {1} plugins'.format(
        hook_name, len(loaded_plugins)))
    
    for plugin in loaded_plugins:
        try:
            hook = getattr(plugin, hook_name, None)
            if hook:
                log(LOG_DEBUG, 'Plugin system: Calling hook {0} on plugin {1}'.format(
                    hook_name, plugin.get_name()))
                result = hook(*args, **kwargs)
                if result is not None:
                    log(LOG_DEBUG, 'Plugin system: Plugin {1} returned result for hook {0}'.format(
                        hook_name, plugin.get_name()))
                    return result
                else:
                    log(LOG_DEBUG, 'Plugin system: Plugin {1} returned None for hook {0}'.format(
                        hook_name, plugin.get_name()))
        except Exception as e:
            log(LOG_ERROR, 'Plugin system: Error in plugin {0} hook {1}: {2}'.format(
                plugin.get_name(), hook_name, e))
    return None

def cleanup_plugins():
    """Cleanup all loaded plugins."""
    log(LOG_VERBOSE, 'Plugin system: Cleaning up {0} plugins'.format(len(loaded_plugins)))
    for plugin in loaded_plugins:
        try:
            log(LOG_DEBUG, 'Plugin system: Cleaning up plugin {0}'.format(plugin.get_name()))
            plugin.cleanup()
        except Exception as e:
            log(LOG_ERROR, 'Plugin system: Error cleaning up plugin {0}: {1}'.format(
                plugin.get_name(), e))
    loaded_plugins.clear()
    log(LOG_VERBOSE, 'Plugin system: Cleanup complete')

class Addr(tuple):
    '''Data structure for storing socket addresses, that provides parsing
    methods and a nice string representation'''
    def __new__(cls, arg, *args):
        '''This is necessary because tuple is an immutable data type, so
        inheritance rules are a bit funny.'''
        # I have some idea I should be using super() here
        if args:
            return tuple.__new__(cls, arg)
        else:
            a = stringtosockaddr(arg)
            return tuple.__new__(cls, a)

    def __init__(self, *args):
        '''Adds the host, port and family attributes to the addr tuple.
        If a single parameter is given, tries to parse it as an address string
        '''
        try:
            addr, family = args
            self.host, self.port = self[:2]
            self.family = family
        except ValueError:
            self.host, self.port = self[:2]
            self.family = valid_addr(self.host)

    def __str__(self):
        '''If self.family is AF_INET or AF_INET6, this provides a standard
        representation of the host and port. Otherwise it falls back to the
        standard tuple.__str__ method.'''
        try:
            return {
                AF_INET: '{0[0]}:{0[1]}',
                AF_INET6: '[{0[0]}]:{0[1]}'
            }[self.family].format(self)
        except (AttributeError, IndexError, KeyError):
            return tuple.__str__(self)

class Info(dict):
    '''A dict with an overridden str() method for converting to \\key\\value\\
    syntax, and a new parse() method for converting therefrom.'''
    def __init__(self, string = None, **kwargs):
        '''If any keyword arguments are given, add them; if a string is given,
        parse it.'''
        dict.__init__(self, **kwargs)
        if string:
            self.parse(string)

    def __str__(self):
        '''Converts self[key1] == value1, self[key2] == value2[, ...] to
        \\key1\\value1\\key2\\value2\\...'''
        return '\\{0}\\'.format('\\'.join(i for t in list(self.items())
                                            for i in t))

    def parse(self, input):
        '''Converts \\key1\\value1\\key2\\value2\\... to self[key1] = value1,
        self[key2] = value2[, ...].
        Note that previous entries in self are not deleted!'''
        input = input.strip('\\')
        while True:
            bits = input.split('\\', 2)
            try:
                self[bits[0]] = bits[1]
                input = bits[2]
            except IndexError:
                break

class Server(object):
    '''Data structure for tracking server timeouts and challenges'''
    def __init__(self, addr, connection_type='udp'):
        # docstring TODO
        self.addr = addr
        self.sock = outSocks[addr.family]
        self.lastactive = 0
        self.timeout = 0
        self.connection_type = connection_type  # 'udp' or 'websocket'

    def __bool__(self):
        '''Server has replied to a challenge'''
        return bool(self.lastactive)

    def __str__(self):
        '''Returns a string representing the host and port of this server'''
        return str(self.addr)

    def set_timeout(self, value):
        '''Sets the time after which the server will be regarded as inactive.
        Will never shorten a server's lifespan'''
        self.timeout = max(self.timeout, value)

    def timed_out(self):
        '''Returns True if the server has been idle for longer than the times
        specified in the config module'''
        return time() > self.timeout

    def send_challenge(self):
        '''Sends a getinfo challenge and records the current time'''
        self.challenge = challenge()
        packet = b'\xff\xff\xff\xffgetinfo ' + self.challenge.encode('ascii')
        log(LOG_DEBUG, '>> {0}: {1!r}'.format(self, packet))
        safe_send(self.sock, packet, self.addr)
        self.set_timeout(time() + config.CHALLENGE_TIMEOUT)

    def infoResponse(self, data):
        '''Returns True if the info given is as complete as necessary and
        the challenge returned matches the challenge sent'''
        addrstr = '<< {0}'.format(self)
        if not data.startswith('infoResponse'):
            log(LOG_VERBOSE, addrstr, 'unexpected packet on challenge socket, '
                                      'ignored')
            return False
        addrstr += ': infoResponse:'
        # find the beginning of the infostring
        for i, c in enumerate(data):
            if c in ' \\\n':
                break
        infostring = data[i + 1:]
        if not infostring:
            log(LOG_VERBOSE, addrstr, 'no infostring found')
            return False
        info = Info(infostring)
        try:
            name = info['hostname']
            if info['challenge'] != self.challenge:
                log(LOG_VERBOSE, addrstr, 'mismatched challenge: '
                    '{0!r} != {1!r}'.format(info['challenge'], self.challenge))
                return False
            self.protocols = info['protocol'].split(',')
            self.empty = (info['clients'] == '0')
            self.full = (info['clients'] == info['sv_maxclients'])
        except KeyError as ex:
            log(LOG_VERBOSE, addrstr, 'info key missing:', ex)
            return False
        if self.lastactive:
            log(LOG_VERBOSE, addrstr, 'verified')
        else:
            log(LOG_VERBOSE, addrstr, 'verified, added to list '
                                      '({0})'.format(count_servers()))
        self.lastactive = time()
        self.set_timeout(self.lastactive + config.SERVER_TIMEOUT)
        return True

# Ideally, we should have a proper object to subclass sockets or something.
def safe_send(sock, data, addr):
    '''Network failures happen sometimes. When they do, it's best to just keep
    going and whine about it loudly than die on the exception.'''
    if sock.type == SOCK_STREAM: #ws connection
        if sock not in ws_connections: #double check this still exists
            log(LOG_ERROR, 'ERROR: WebSocket connection', addr, 'no longer exists')
            return
        else:
            try:
                ws = ws_connections[sock]['ws']
                ws_data = ws.send(BytesMessage(data=data))
                sock.sendall(ws_data)
            except sockerr as err:
                log(LOG_ERROR, 'ERROR: sending to WebSocket', addr, 'failed with error:',
                    err.strerror)
            except Exception as err:
                log(LOG_ERROR, 'ERROR: sending to WebSocket', addr, 'failed:', str(err))

    else:
        try:
            sock.sendto(data, addr)
        except sockerr as err:
            log(LOG_ERROR, 'ERROR: sending to', addr, 'failed with error:',
                err.strerror)
        except Exception as err:
                log(LOG_ERROR, 'ERROR: sending to WebSocket', addr, 'failed:', str(err))

def find_featured(addr):
    # docstring TODO
    # just in case it's an Addr
    for (label, addrs) in list(config.featured_servers.items()):
        if addr in list(addrs.keys()):
            return label
    else:
        return None

def prune_timeouts(slist = servers[None]):
    '''Removes from the list any items whose timeout method returns true'''
    # iteritems gives RuntimeError: dictionary changed size during iteration
    for (addr, server) in list(slist.items()):
        # Skip puppet servers - they should not be pruned due to timeout
        if find_featured(addr) == 'puppet':
            continue
        if server.timed_out():
            del slist[addr]
            remstr = str(count_servers())
            if server.lastactive:
                log(LOG_VERBOSE, '{0} dropped due to {1}s inactivity '
                            '({2})'.format(server, time() - server.lastactive, remstr))
            else:
                log(LOG_VERBOSE, '{0} dropped: no response '
                            '({1})'.format(server, remstr))

def challenge():
    '''Returns a string of config.CHALLENGE_LENGTH characters, chosen from
    those greater than ' ' and less than or equal to '~' (i.e. isgraph)
    Semicolons, backslashes and quotes are precluded because the server won't
    put them in an infostring; forward slashes are not allowed because the
    server's parsing tools can recognise them as comments
    Percent symbols: these used to be disallowed, but subsequent to Tremulous
    SVN r1148 they should be okay. Any server older than that will translate
    them into '.' and therefore fail to match.
    For compatibility testing purposes, I've temporarily disallowed them again.
    '''
    valid = [c for c in map(chr, list(range(0x21, 0x7f))) if c not in '\\;%\"/']
    return ''.join(choice(valid) for _ in range(config.CHALLENGE_LENGTH))

def count_servers(slist = servers):
    # docstring TODO
    return sum(map(len, list(servers.values())))

def gamestat(addr, data):
    '''Delegates to log_gamestat, cutting the first token (that it asserts is
    'gamestat') from the data'''
    assert data.startswith('gamestat')
    try:
        log_gamestat(addr, data[len('gamestat'):].lstrip())
    except ValueError as err:
        log(LOG_PRINT, '<< {0}: Gamestat not logged'.format(addr), err)
        return
    log(LOG_VERBOSE, '<< {0}: Recorded gamestat'.format(addr))

def getmotd(sock, addr, data):
    '''A client getmotd request: log the client information and then send the
    response'''
    addrstr = '<< {0}'.format(addr)
    try:
        _, infostr = data.split('\\', 1)
    except ValueError:
        infostr = ''
    info = Info(infostr)
    rinfo = Info()
    try:
        log_client(addr, info)
    except KeyError as err:
        log(LOG_PRINT, addrstr, 'Client not logged: missing info key',
            err, sep = ': ')
    except ValueError as err:
        log(LOG_PRINT, addrstr, 'Client not logged', err, sep = ': ')
    else:
        log(LOG_VERBOSE, addrstr, 'Recorded client stat', sep = ': ')

    try:
        rinfo['challenge'] = info['challenge']
    except KeyError:
        log(LOG_VERBOSE, addrstr, 'Challenge missing or invalid', sep = ': ')
    rinfo['motd'] = config.getmotd()
    if not rinfo['motd']:
        return

    response = b'\xff\xff\xff\xffmotd ' + str(rinfo).encode('ascii')
    log(LOG_DEBUG, '>> {0}: {1!r}'.format(addr, response))
    safe_send(sock, response, addr)

def filterservers(slist, af, protocol, empty, full, client_type='udp'):
    '''Return those servers in slist that test true (have been verified) and:
    - whose protocols contain `protocol'
    - if `ext' is not set, are IPv4
    - if `empty' is not set, are not empty
    - if `full' is not set, are not full
    - if client_type is 'websocket', only return WebSocket servers
    - if client_type is 'udp', only return UDP servers (or servers without connection_type for backward compatibility)'''
    return [s for s in slist if s
            and af in (AF_UNSPEC, s.addr.family)
            and not s.timed_out()
            and protocol in s.protocols
            and (empty or not s.empty)
            and (full  or not s.full)
            and ((client_type == 'websocket' and getattr(s, 'connection_type', 'udp') == 'websocket')
                 or (client_type == 'udp' and getattr(s, 'connection_type', 'udp') != 'websocket'))]

def gsr_formataddr(addr):
    sep  = b'\\' if addr.family == AF_INET else b'/'
    host = inet_pton(addr.family, addr.host)
    port = bytes([addr.port >> 8, addr.port & 0xff])
    return sep + host + port

def getservers(sock, addr, data):
    '''On a getservers or getserversExt, construct and send a response'''

    # Determine client type based on socket
    client_type = 'udp'  # default to UDP
    if sock.type == SOCK_STREAM:
        client_type = 'websocket'
        log(LOG_VERBOSE, 'getservers: WebSocket client request from {0}'.format(addr))
    else:
        log(LOG_DEBUG, 'getservers: UDP client request from {0}'.format(addr))

    # Call plugin hooks
    log(LOG_DEBUG, 'getservers: Calling plugin hooks for {0}'.format(addr))
    result = call_plugins_hook('on_getservers', sock, addr, data)
    if result is True:
        log(LOG_VERBOSE, 'getservers: Plugin handled request from {0}'.format(addr))
        return  # Plugin handled this getservers request

    tokens = data.split()
    ext = (tokens.pop(0) == b'getserversExt')
    if ext:
        try:
            game = tokens.pop(0).decode('ascii')
        except IndexError:
            game = ''
        if game != 'Tremulous':
            log(LOG_VERBOSE, '<< {0}: ext but not Tremulous, '
                             'ignored'.format(addr))
            return
    try:
        protocol = tokens.pop(0).decode('ascii')
    except IndexError:
        log(LOG_VERBOSE, '<< {0}: no protocol specified'.format(addr))
        return
    empty, full = b'empty' in tokens, b'full' in tokens
    if ext:
        family = (AF_INET  if b'ipv4' in tokens
             else AF_INET6 if b'ipv6' in tokens
             else AF_UNSPEC)
    else:
        family = AF_INET

    max = config.GSR_MAXSERVERS
    packets = {None: list()}
    for label in list(servers.keys()):
        # dict of lists of lists
        if ext:
            packets[label] = list()
            # Filter servers by client type: WebSocket clients only see WebSocket servers, UDP clients only see UDP servers
            # For backward compatibility, if server has no connection_type, show it to UDP clients
            filtered = filterservers(list(servers[label].values()),
                                     family, protocol, empty, full, client_type)
            while len(filtered) > 0:
                packets[label].append(filtered[:config.GSR_MAXSERVERS])
                filtered = filtered[config.GSR_MAXSERVERS:]
        else:
            # Filter servers by client type: WebSocket clients only see WebSocket servers, UDP clients only see UDP servers
            # For backward compatibility, if server has no connection_type, show it to UDP clients
            filtered = filterservers(list(servers[label].values()),
                                     family, protocol, empty, full, client_type)
            if not packets[None]:
                packets[None].append(filtered[:config.GSR_MAXSERVERS])
                filtered = filtered[config.GSR_MAXSERVERS:]
            while len(filtered) > 0:
                space = config.GSR_MAXSERVERS - len(packets[None][-1])
                if space:
                    packets[None][-1].extend(filtered[:space])
                    filtered = filtered[space:]
                else:
                    packets[None].append(filtered[:config.GSR_MAXSERVERS])
                    filtered = filtered[config.GSR_MAXSERVERS:]

    if ext:
        start = b'\xff\xff\xff\xffgetserversExtResponse'
    else:
        start = b'\xff\xff\xff\xffgetserversResponse'

    index = 1
    numpackets = sum(len(ps) for ps in list(packets.values()))
    if numpackets == 0:
        # send an empty packet
        numpackets = 1
        packets[None] = [[]]
    for label, packs in list(packets.items()):
        if label is None:
            label = ''
        for packet in packs:
            message = start
            if ext:
                message += b'\0' + str(index).encode('ascii') + b'\0' + str(numpackets).encode('ascii') + b'\0' + label.encode('ascii')
            message += b''.join(gsr_formataddr(s.addr) for s in packet)
            message += b'\\'
            log(LOG_DEBUG, '>> {0}: {1} servers'.format(addr, len(packet)))
            log(LOG_DEBUG, '>> {0}: {1!r}'.format(addr, message))
            # SECURITY FIX: Removed print(message) to prevent information disclosure
            safe_send(sock, message, addr)
            index += 1
    npstr = '1 packet' if numpackets == 1 else '{0} packets'.format(numpackets)
    log(LOG_VERBOSE, '>> {0}: getservers{1}Response: sent '
                     '{2}'.format(addr, 'Ext' if ext else '', npstr))

def heartbeat(addr, data, sock=None):
    '''In response to an incoming heartbeat, find the associated server.
    If this is a flatline, delete it, otherwise send it a challenge,
    creating it if necessary and adding it to the list.'''
    # Call plugin hooks
    log(LOG_DEBUG, 'heartbeat: Calling plugin hooks for {0}'.format(addr))
    result = call_plugins_hook('on_heartbeat', addr, data)
    if result is True:
        log(LOG_VERBOSE, 'heartbeat: Plugin handled request from {0}'.format(addr))
        return  # Plugin handled this heartbeat

    # Determine connection type based on socket type
    connection_type = 'udp'  # default to UDP
    if sock and sock.type == SOCK_STREAM:
        connection_type = 'websocket'
        log(LOG_DEBUG, 'heartbeat: WebSocket heartbeat from {0}'.format(addr))

    label = find_featured(addr)
    addrstr = '<< {0}:'.format(addr)
    if b'dead' in data:
        if label is None:
            if addr in list(servers[None].keys()):
                log(LOG_VERBOSE, addrstr, 'flatline, dropped')
                del servers[label][addr]
            else:
                log(LOG_DEBUG, addrstr,
                    'flatline from unknown server, ignored')
        else:
            # FIXME: we kind of assume featured servers don't go down
            log(LOG_DEBUG, addrstr, 'flatline from featured server :(')
    elif config.max_servers >= 0 and count_servers() >= config.max_servers:
        log(LOG_PRINT, 'Warning: max server count exceeded, '
                       'heartbeat from', addr, 'ignored')
    else:
        # fetch or create a server record
        label = find_featured(addr)
        if addr in list(servers[label].keys()):
            s = servers[label][addr]
            # Update connection type if server already exists
            s.connection_type = connection_type
        else:
            s = Server(addr, connection_type)
        s.send_challenge()
        servers[label][addr] = s

def filterpacket(data, addr):
    '''Called on every incoming packet, checks if it should immediately be
    dropped, returning the reason as a string'''
    # forging a packet with source port 0 can lead to an error on response
    if addr.port == 0:
        return 'invalid port'
    if not data.startswith(b'\xff\xff\xff\xff'):
        return 'no header'
    if config.ignore(addr.host):
        return 'blacklisted'

def deserialise():
    """Read server list from cache file with file locking to prevent race conditions."""
    count = 0
    try:
        import fcntl
        with open('serverlist.txt', 'r') as f:
            fcntl.flock(f, fcntl.LOCK_SH)  # Shared lock for reading
            for line in f:
                if not line:
                    continue
                try:
                    addr = Addr(line)
                except sockerr as err:
                    log(LOG_ERROR, 'Could not parse address in serverlist.txt',
                        repr(line), err.strerror, sep = ': ')
                except ValueError as err:
                    log(LOG_ERROR, 'Could not parse address in serverlist.txt',
                        repr(line), str(err), sep = ': ')
                else:
                    addrstr = '<< {0}:'.format(addr)
                    log(LOG_DEBUG, addrstr, 'Read from the cache')
                    if addr.family not in list(outSocks.keys()):
                         famstr = {AF_INET: 'IPv4', AF_INET6: 'IPv6'}[addr.family]
                         log(LOG_PRINT, addrstr, famstr,
                             'not available, dropping from cache')
                    else:
                         # fake a heartbeat to verify the server as soon as
                         # possible could cause an initial flood of traffic, but
                         # unlikely to be anything that it can't handle
                         heartbeat(addr, b'')
                         count += 1
    except ImportError:
        # Windows or other systems without fcntl - use atomic operations
        with open('serverlist.txt', 'r') as f:
            for line in f:
                if not line:
                    continue
                try:
                    addr = Addr(line)
                except sockerr as err:
                    log(LOG_ERROR, 'Could not parse address in serverlist.txt',
                        repr(line), err.strerror, sep = ': ')
                except ValueError as err:
                    log(LOG_ERROR, 'Could not parse address in serverlist.txt',
                        repr(line), str(err), sep = ': ')
                else:
                    addrstr = '<< {0}:'.format(addr)
                    log(LOG_DEBUG, addrstr, 'Read from the cache')
                    if addr.family not in list(outSocks.keys()):
                         famstr = {AF_INET: 'IPv4', AF_INET6: 'IPv6'}[addr.family]
                         log(LOG_PRINT, addrstr, famstr,
                             'not available, dropping from cache')
                    else:
                         # fake a heartbeat to verify the server as soon as
                         # possible could cause an initial flood of traffic, but
                         # unlikely to be anything that it can't handle
                         heartbeat(addr, b'')
                         count += 1
    log(LOG_VERBOSE, 'Read', count, 'servers from cache')

def serialise():
    """Write server list to cache file with file locking to prevent race conditions."""
    try:
        import fcntl
        # SECURITY FIX: Use atomic write with temporary file and rename
        temp_file = 'serverlist.txt.tmp'
        with open(temp_file, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock for writing
            f.write('\n'.join(str(s) for sl in list(servers.values()) for s in sl))
        # Atomic rename on Unix systems
        import os
        os.rename(temp_file, 'serverlist.txt')
        log(LOG_PRINT, 'Wrote serverlist.txt')
    except ImportError:
        # Windows or other systems without fcntl - use atomic operations
        import os
        temp_file = 'serverlist.txt.tmp'
        with open(temp_file, 'w') as f:
            f.write('\n'.join(str(s) for sl in list(servers.values()) for s in sl))
        # Atomic rename on Windows
        os.replace(temp_file, 'serverlist.txt')
        log(LOG_PRINT, 'Wrote serverlist.txt')

# Pre-initialize plugins before binding sockets
pre_initialize_plugins()

try:
    all_ports = sorted(set(config.ports + [config.challengeport]))

    # Track which socket families successfully bound
    ipv4_bound = False
    ipv6_bound = False

    # IPv4 socket binding
    if config.ipv4 and config.listen_addr:
        try:
            log(LOG_PRINT, 'IPv4: Listening on', config.listen_addr,
                           'ports', ', '.join(str(port) for port in all_ports))
            for port in config.ports:
                s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
                s.bind((config.listen_addr, port))
                inSocks.append(s)
            outSocks[AF_INET] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            outSocks[AF_INET].bind((config.listen_addr, config.challengeport))
            ipv4_bound = True
            log(LOG_VERBOSE, 'IPv4 socket binding successful')
        except sockerr as err:
            log(LOG_ERROR, 'IPv4: Failed to bind socket to {0}:{1} - {2}'.format(
                config.listen_addr, config.challengeport, err.strerror))
            # IPv4 is critical, so we fail if it doesn't work
            raise

    # IPv6 socket binding
    if config.ipv6:
        if not config.listen6_addr:
            log(LOG_PRINT, 'IPv6: Warning: config.ipv6 is enabled but config.listen6_addr is not set, skipping IPv6')
        else:
            try:
                log(LOG_PRINT, 'IPv6: Listening on', config.listen6_addr,
                               'ports', ', '.join(str(port) for port in all_ports))
                for port in config.ports:
                    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
                    s.bind((config.listen6_addr, port))  # FIXED: Use listen6_addr instead of listen_addr
                    inSocks.append(s)
                outSocks[AF_INET6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
                outSocks[AF_INET6].bind((config.listen6_addr, config.challengeport))
                ipv6_bound = True
                log(LOG_VERBOSE, 'IPv6 socket binding successful')
            except sockerr as err:
                log(LOG_PRINT, 'IPv6: Warning: Failed to bind socket to {0}:{1} - {2}'.format(
                    config.listen6_addr, config.challengeport, err.strerror))
                log(LOG_PRINT, 'IPv6: Continuing with IPv4 only (graceful degradation)')

    # WebSocket socket binding
    if (ipv4_bound or ipv6_bound) and config.use_ws and config.ws_ports:
        try:
            all_ws_ports = sorted(set(config.ws_ports))
            log(LOG_PRINT, 'WebSockets: Listening on ports', ', '.join(str(port) for port in all_ws_ports))
            for port in all_ws_ports:
                s = socket(AF_INET, SOCK_STREAM)
                s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                s.bind((config.listen_addr, port))
                s.listen(5)
                s.setblocking(False)
                inSocks.append(s)
            usingWs = True
            log(LOG_VERBOSE, 'WebSocket socket binding successful')
        except sockerr as err:
            log(LOG_ERROR, 'WebSockets: Failed to bind socket to port {0} - {1}'.format(
                port, err.strerror))
            # WebSocket is non-critical, log warning but continue
            log(LOG_PRINT, 'WebSockets: Warning: WebSocket binding failed, continuing without WebSocket support')

    if not inSocks and not outSocks:
        log(LOG_ERROR, 'Error: Not listening on any sockets, aborting')
        log(LOG_ERROR, 'IPv4 bound: {0}, IPv6 bound: {1}'.format(ipv4_bound, ipv6_bound))
        exit(1)

except sockerr as err:
    log(LOG_ERROR, 'Couldn\'t initialise sockets:', err.strerror)
    log(LOG_ERROR, 'IPv4 bound: {0}, IPv6 bound: {1}'.format(ipv4_bound, ipv6_bound))
    exit(1)

try:
    deserialise()
except IOError as err:
    if err.errno != ENOENT:
        log(LOG_ERROR, 'Error reading serverlist.txt:', err.strerror)

# Complete plugin initialization after socket binding
initialize_plugins()

def processmessage(sock, data, addr):
    saddr = Addr(addr, sock.family)
    # for logging
    addrstr = '<< {0}:'.format(saddr)
    log(LOG_DEBUG, addrstr, repr(data))
    res = filterpacket(data, saddr)
    if res:
        log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
        return
    data = data[4:] # skip header
    # assemble a list of callbacks, to which we will give the
    # socket to respond on, the address of the request, and the data
    responses = [
        # this looks like it should be a dict but since we use
        # startswith it wouldn't really improve matters
        (b'gamestat', lambda s, a, d: gamestat(a, d)),
        (b'getmotd', getmotd),
        (b'getservers', getservers),
        # getserversExt also starts with getservers
        (b'heartbeat', lambda s, a, d: heartbeat(a, d, sock)),
        # infoResponses will arrive on an outSock
    ]
    for (name, func) in responses:
        if data.startswith(name):
            func(sock, saddr, data)
            break
    else:
        log(LOG_VERBOSE, addrstr, 'unrecognised content:', repr(data))

def mainloop():
    try:
        ret = select(chain(inSocks, list(outSocks.values()), list(ws_connections.keys())), [], [])
        ready = ret[0]
    except selecterror as err:
        # select can be interrupted by a signal: if it wasn't a fatal signal,
        # we don't care
        if err.errno == EINTR:
            return
        raise
    prune_timeouts()

    for sock in ready:
        if usingWs and sock.type == SOCK_STREAM: #ws connection
            if sock in inSocks: # new ws connection
                try:
                    ws_sock, addr = sock.accept()
                    ws_sock.setblocking(False)
                    
                    ws = WSConnection(ConnectionType.SERVER)
                    ws_connections[ws_sock] = {'ws': ws, 'addr': addr}
                    log(LOG_VERBOSE, f"New WebSocket connection from {addr}")
                except Exception as e:
                    log(LOG_ERROR, f"Error accepting WebSocket connection: {e}")

            elif sock in ws_connections: #existing ws connection
                try:
                    data = sock.recv(4096)
                    outgoing_data = b''

                    if not data:
                        del ws_connections[sock]
                        sock.close()
                        continue

                    ws = ws_connections[sock]['ws']
                    addr = ws_connections[sock]['addr']
                    ws.receive_data(data)

                    for event in ws.events():

                        if isinstance(event, Request):
                            if event.subprotocols:
                                outgoing_data = ws.send(AcceptConnection(subprotocol=event.subprotocols[0]))
                            else:
                                outgoing_data = ws.send(AcceptConnection())
                            sock.sendall(outgoing_data)
                        
                        elif isinstance(event, BytesMessage):
                            message_data = event.data
                            if(message_data.find(b'portx') != -1): #disregard emscripten port idenfier message
                                break
                            processmessage(sock, message_data, addr)

                        elif isinstance(event, Ping):
                            outgoing_data = ws.send(Pong(payload=event.payload))
                            sock.sendall(outgoing_data)

                        elif isinstance(event, CloseConnection):
                            outgoing_data = ws.send(event.response())
                            sock.sendall(outgoing_data)
                            del ws_connections[sock]
                            sock.close()
                            break

                except Exception as e:
                    log(LOG_ERROR, f"WebSocket error: {e}")
                    if sock in ws_connections: #could be gone by this point
                        del ws_connections[sock]
                    sock.close()

        elif sock in inSocks: # udp
            # FIXME: 2048 magic number
            (data, addr) = sock.recvfrom(2048)
            processmessage(sock, data, addr)

    for sock in list(outSocks.values()):
        if sock in ready:
            (data, addr) = sock.recvfrom(2048)
            saddr = Addr(addr, sock.family)
            # for logging
            addrstr = '<< {0}:'.format(saddr)
            log(LOG_DEBUG, addrstr, repr(data))
            res = filterpacket(data, saddr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:] # skip header
            #convert data to string
            if isinstance(data, bytes):
                data = data.decode('ascii')
            # the outSocks are for getinfo challenges, so any response should
            # be from a server already known to us
            label = find_featured(addr)
            # if label = find_featured(addr) is not None, it should be the
            # case that servers[label][addr] exists
            # SECURITY FIX: Replace assertion with proper error handling
            if label is None and addr not in list(servers[None].keys()):
                log(LOG_VERBOSE, addrstr, 'rejected (unsolicited)')
                continue
            # this has got to be an infoResponse, right?
            servers[label][addr].infoResponse(data)

try:
    while True:
        mainloop()
except KeyboardInterrupt: #TODO: We need to gracefully close all existing ws connections
    stderr.write('Interrupted')
    signal(SIGINT, SIG_DFL)
    # The following kill stops the finally from running,
    # so let's do the serialise ourselves.
    serialise()
    kill(getpid(), SIGINT)
finally:
    # Cleanup plugins
    cleanup_plugins()
    serialise()
