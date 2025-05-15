''' Peach Server

A remote endpoint to connect the Peach Ghidra plugin into for a more flexible plugin/script development.

Useful for creating Python 3 scripts, lightweight Ghidra plugins through Peach's client support, or workloads that are better run on servers

Utilizes Python's socket server and ForkingMixIn to easily handle releasing plugin resources.

Installed as a namespace package to allow for plugins.
See: plugins/defaults/__init__.py for an example of how to create a server plugin.
'''
import argparse
import importlib
import json
import logging
import pkgutil
import socket
import socketserver
from pathlib import Path
from tempfile import TemporaryDirectory

from jschema_to_python.to_json import to_json as sarif_to_json
from sarif_om import SarifLog

import peach.plugins
from peach.sarif_tools import write_sarif

log = logging.getLogger(__name__)

def main():
    ''' Parse arguments and run server '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--host', default='localhost', help='Address to bind to')
    parser.add_argument('-p', '--port', default=1124, help='Port to bind to', type=int)
    parser.add_argument('-i', '--instance_dir', default=None, help='Directory for plugins to write to or read from')

    args = parser.parse_args()
    run_server(args.host, args.port, args.instance_dir)

def run_server(host, port, instance_dir):
    ''' Setup logging and launch server '''
    logging.basicConfig(filename='peach.log', level=logging.DEBUG)
    logging.root.addHandler(logging.StreamHandler())

    def run(instance_dir):
        instance_dir = Path(instance_dir).resolve()
        with PeachServer((host, port), PeachHandler, instance_dir) as server:
            server.serve_forever()

    if instance_dir is None:
        with TemporaryDirectory() as instance_dir:
            run(instance_dir)
    else:
        run(instance_dir)

class PeachServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    def __init__(self, server_addr, handlerClass, instance_dir):
        ''' Load installed plugins '''
        super().__init__(server_addr, handlerClass)
        log.debug(f'Using instance directory {instance_dir}')
        self.instance_dir = instance_dir
        self.plugins  = discover_plugins()
        log.info(f'Discovered plugins: {self.plugins}')

        self.plugin_methods = []
        for name, module in sorted(self.plugins.items()):
            # plugins will be named `peach.plugins.<custom_name>`, we only care about <custom_name>
            plugin_name = name.split('.', 2)[-1]
            methods = module.get_methods(self.instance_dir / plugin_name)
            self.plugin_methods.extend(methods)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

class PeachHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Read in request
        data = self.request.makefile().readline()
        log.debug(f'Received: {data}')
        data = json.loads(data)

        match data:
            # Get all available plugin information
            case {'method': 'get_plugins'}:
                self.request.sendall(rpc_result(self.server.plugin_methods))
             # A request to a specific plugin
            case {'method': method, 'params': params}:
                plugin, _, method = method.rpartition('.')
                # We pass into the plugin the directory where they should write/read resources.
                plugin_dir = self.server.instance_dir / plugin
                if not plugin_dir.exists():
                    plugin_dir.mkdir()

                name = f'peach.plugins.{plugin}'
                if name not in self.server.plugins:
                    self.request.sendall(rpc_error(f'No plugin {plugin}'))
                    log.error(f'No plugin {plugin}')
                    return

                # Call the analysis
                func = getattr(self.server.plugins[name], method)
                if isinstance(params, dict):
                    result = func(**params, plugin_dir = plugin_dir)
                elif isinstance(params, list):
                    result = func(*params, plugin_dir = plugin_dir)

                # SarifLog -> string
                if isinstance(result, SarifLog):
                    result = sarif_to_json(result)
                    write_sarif(result, f'{plugin}_{method}.sarif')
                # String -> dict
                if isinstance(result, str):
                    result = json.loads(result)
                # dict -> String
                log.debug('Sending %s' % json.dumps(result, indent=2))

                self.request.sendall(rpc_result(result))
            case _:
                self.request.sendall(rpc_error('Malformed request'))
                log.error(f'Malformed request {data}')

def rpc_result(result):
    return f"{json.dumps({'result': result})}".encode()

def rpc_error(message):
    return f"{json.dumps({'error': {'message': message}})}".encode()

def discover_plugins():
    ''' Find plugins according to:
        https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/
    '''

    discovered_plugins = {
        name: importlib.import_module(name)
        for finder, name, ispkg
        in iter_namespace(peach.plugins)
    }
    return discovered_plugins

def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + '.')

if __name__ == '__main__':
    main()
