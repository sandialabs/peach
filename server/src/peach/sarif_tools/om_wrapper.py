''' Helper functions for creating SARIF files. '''

import base64
import datetime
import mimetypes
import socket
import subprocess
import sys
from pathlib import Path

import sarif_om
from jschema_to_python.to_json import to_json as sarif_to_json

from .utils import get_root_git, get_url_branch_and_commit, sha256sum


def example_run():
    from collections import namedtuple
    Encoder = namedtuple('Encoder', ['classes_'])
    enc = Encoder(['int', 'uint'])

    t   = tool('DS', '1.0', 'github.com', properties=property_bag(label='return_type'))
    tax = label_encoder_taxonomy('types', enc)
    a   = artifact_file('analyzed_file', add_contents=True)
    vc  = version_control('.')
    i   = create_invocation('sarif_tools.py')
    re1 = addr_classification('', 'return_type', 0, 'types', 0, artifact_id=0, properties=property_bag(confidence=[.8,.2]))
    re2 = addr_classification('', 'return_type', 1, 'types', 0, artifact_id=0, properties=property_bag(confidence=[.7,.3]))
    r   = sarif_om.Run(t, taxonomies=[tax], invocations=[i], artifacts=[a], version_control_provenance=[vc], results=[re1, re2])
    log = sarif_log(r)
    Path('example.sarif').write_text(sarif_to_json(log))
    print(sarif_to_json(log))

def sarif_log(runs, properties=None):
    return log(runs, properties)

def log(runs, properties=None):
    ''' Create the SarifLog with the given runs '''
    if not isinstance(runs, list):
        runs = [runs]
    return sarif_om.SarifLog(
            runs,
            '2.1.0',
            "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            properties=properties)

def run(tool, **kwargs):
    ''' See sarif_om.Run '''
    return sarif_om.Run(tool, **kwargs)

def tool(name, version=None, information_uri=None, **kwargs):
    ''' Create a Tool object based on given information '''
    tc = sarif_om.ToolComponent(name, version=version, information_uri=information_uri, **kwargs)
    return sarif_om.Tool(tc)

def logical_column(loc_name, kind, comment, col, **kwargs):
    ''' Create a result object based on the logical location (like function name)
        that will add a column to the result table '''
    loc = logical_location(loc_name, kind)
    properties = add_column_property(col, comment)
    return result(comment,
                  col,
                  locations=loc,
                  properties=properties,
                  **kwargs)

def addr_comment(address, artifact_id, comment, **kwargs):
    ''' Create a result object based on the address location
        that will add a comment to the Ghidra listing '''
    properties = listing_comment_property(comment)
    addr_location = physical_location(address, artifact_id)
    ruleid = kwargs.pop('ruleid', 'listing/comment')
    return result(comment,
                  rule_id=ruleid,
                  locations=addr_location,
                  properties=properties,
                  **kwargs)

def addr_classification(message, rule_id, address, taxa_name, taxa_id, artifact_id, **kwargs):
    ''' Create a result object based on the address location that will be based on
        a taxonomy so will add a column '''
    addr_location = physical_location(address, artifact_id)
    taxa_ref = taxa_reference(taxa_id, taxa_name)
    return result(message, rule_id, taxa=[taxa_ref], locations=addr_location, **kwargs)

def result(message, rule_id, kind='informational', level='none', locations=None, **kwargs):
    message = sarif_om.Message(text=message)

    if locations is not None:
        if not isinstance(locations, list):
            locations = [locations]

    return sarif_om.Result(
                message,
                rule_id=rule_id,
                kind=kind,
                level=level,
                locations=locations,
                **kwargs
           )

def create_invocation(cmdline=None, success=True, working_dir=None, do_run=False, capture=False):
    ''' Create an Invocation object '''
    if cmdline is None:
        cmdline = sys.argv
    if isinstance(cmdline, str):
        cmdline = cmdline.split()
    if working_dir is None:
        working_dir = Path.cwd()
    else:
        working_dir = Path(working_dir)
    start_utc = datetime.datetime.utcnow().isoformat()
    end_utc   = None
    properties = None
    if do_run:
        ret = subprocess.run(cmdline, capture_output=capture)
        if capture:
            properties = property_bag(stdout=ret.stdout.decode(), stderr=ret.stderr.decode())
        success = ret.returncode == 0
        end_utc = datetime.datetime.utcnow().isoformat()
    return sarif_om.Invocation(success,
            command_line=' '.join(cmdline),
            start_time_utc=start_utc,
            end_time_utc = end_utc,
            working_directory=sarif_om.ArtifactLocation(uri=working_dir.resolve()),
            machine=socket.gethostname(),
            properties=properties)

def version_control(path=None):
    ''' Get version control information '''
    if path is None:
        path = Path.cwd()
    else:
        path = Path(path)
    try:
        path = get_root_git(path)
    except ValueError:
        pass
    url, branch, commit = get_url_branch_and_commit(path)
    if not branch:
        return None
    return sarif_om.VersionControlDetails(url,
            branch = branch,
            revision_id = commit,
            mapped_to = sarif_om.ArtifactLocation(uri_base_id=path.resolve()))

def artifact_file(filename, do_hash=True, add_contents=False, add_hostname=False, **kwargs):
    ''' Get artification information of a file '''
    path     = Path(filename)
    uri      = filename
    hashes   = None
    roles    = getattr(kwargs, 'roles', None)
    length   = None
    contents = None
    hn_prop  = None
    if path.exists():
        uri = f'{path.resolve()}'
        if path.is_dir():
            roles = getattr(kwargs, 'roles', [])
            if 'directory' not in roles:
                roles.append('directory')
        else:
            length = path.stat().st_size
            if do_hash: hashes = {'sha-256': sha256sum(filename)}
            if add_contents:
                filetype = mimetypes.guess_type(path)[0]
                if filetype and filetype.startswith('text'):
                    text   = path.read_text(encoding='utf-8')
                    binary = None
                else:
                    text   = None
                    binary = base64.b64encode(path.read_bytes()).decode()
                contents = sarif_om.ArtifactContent(text=text, binary=binary)
    if add_hostname:
        hn_prop = property_bag(hostname=socket.gethostname())
    location = sarif_om.ArtifactLocation(uri=uri, properties=hn_prop)
    artifact = sarif_om.Artifact(location=location,
                                 roles=roles,
                                 length=length,
                                 hashes = hashes,
                                 contents=contents,
                                 **kwargs)
    return artifact

def logical_location(name, kind='function'):
    log_loc = sarif_om.LogicalLocation(name=name, kind=kind)
    return sarif_om.Location(logical_locations=[log_loc])

def physical_location(addr, artifact_id=None):
    a_loc = None
    if isinstance(addr, str):
        addr = int(addr, 16)

    if artifact_id is not None:
        a_loc = sarif_om.ArtifactLocation(index=artifact_id)
    pl = sarif_om.PhysicalLocation(
            address=sarif_om.Address(addr),
            artifact_location=a_loc
         )
    return sarif_om.Location(physical_location=pl)

def create_graph(graph):
    ''' Create a sarif graph object from a networkx graph '''
    nodes = []
    edges = []
    for n in graph.nodes:
        nodes.append(sarif_om.Node(n, label=sarif_om.Message(text=n)))
    for i, e in enumerate(graph.edges):
        edges.append(sarif_om.Edge(i, e[0], e[1]))

    return sarif_om.Graph(edges=edges, nodes=nodes)

def label_encoder_taxonomy(name, encoder):
    ''' Create a SARIF taxonomy based on a sklearn LabelEncoder '''
    descs = []
    for cls in encoder.classes_:
        descs.append(sarif_om.ReportingDescriptor(cls))
    return sarif_om.ToolComponent(name, taxa=descs)

def taxa_reference(taxa_id, name):
    return sarif_om.ReportingDescriptorReference(
            index=taxa_id,
            tool_component=sarif_om.ToolComponentReference(name=name))

def add_column_property(col, value, visible=True):
    if not visible and not col.startswith('.'):
        col = f'.{col}'
    return property_bag_from_dict({f'viewer/table/{col}': value})

def listing_comment_property(comment):
    return property_bag_from_dict({'listing/comment': comment})

def highlight_property(color):
    return property_bag_from_dict({'listing/highlight': f'#{color}'})

def property_bag(**kwargs):
    ''' Create a property bag based on supplied keyword argument '''
    pb = sarif_om.PropertyBag()
    for key, value in kwargs.items():
        setattr(pb, key, value)
    return pb

def property_bag_from_dict(dic):
    ''' Create a property bag from a Python dictionary '''
    pb = sarif_om.PropertyBag()
    for key, value in dic.items():
        setattr(pb, key, value)
    return pb

def combine_properties(*props):
    d = {}
    for prop in props:
        d.update(prop.__dict__)
    return d
