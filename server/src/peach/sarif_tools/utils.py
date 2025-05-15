''' Utility functions indirectly related to SARIF '''

import configparser
import hashlib
import json
from pathlib import Path

import pandas as pd
from jschema_to_python.to_json import to_json as sarif_to_json
from sarif_om import SarifLog

from peach import sarif_tools

def file_to_sarif(fn, **kwargs):
    ''' Do best effort of converting other potential result formats into SARIF '''
    fn = Path(fn)
    if 'name' not in kwargs:
        kwargs['name'] = fn.name
    if 'uri' not in kwargs:
        kwargs['uri'] = fn.resolve()
    match fn.suffix:
        case '.csv':
            df = pd.read_csv(fn)
        case '.parquet':
            df = pd.read_parquet(fn)
        case '.json':
            df = pd.read_json(fn)
        case ext:
            raise TypeError(f'Unknown extension {ext}')

    return dataframe_to_sarif(df, **kwargs)

def dataframe_to_sarif(df, name, version=None, uri=None, rule_id_col=None, message_col=None, location_cols=None, table_cols=None):
    ''' Convert a pandas DataFrame into a SARIF log file. This will be considered one run.

        Parameters
        ----------
        df: pandas.DataFrame
        name: str
            Name of the tool
        version: str
            Optional version of the tool
        uri: str
            Optional uri for the tool
        rule_id_col: str
            Name of the column to use for the Result rule_id.
                Defaults to 'rule_id' if it exits, otherwise the first unused column
        message_col: str
            Name of the column to use for the Result message text.
                Defaults to 'message' if it exists, otherwise the second unused column
        location_cols: list[str]
            List of column names to use for the Result locations.
        table_cols: list[str]
            List of column names to specify in Peach parlance to be shown on the filter table.
    '''

    # Heuristic what columns are which if not provided
    if not table_cols:
        table_cols = []
    if not location_cols:
        location_cols = []

    if rule_id_col is None:
        # Get first unused
        unknown_cols = (c for c in df.columns if c not in [rule_id_col, message_col, *location_cols, *table_cols])
        rule_id_col = 'rule_id' if 'rule_id' in df.columns else next(unknown_cols)
    if message_col is None:
        unknown_cols = (c for c in df.columns if c not in [rule_id_col, message_col, *location_cols, *table_cols])
        message_col = 'message' if 'message' in df.columns else next(unknown_cols)
    property_cols = [c not in [rule_id_col, message_col, *location_cols] for c in df.columns]

    # Create the log file
    tool = sarif_tools.tool(name, version, uri)
    results = []
    for _, row in df.iterrows():
        # get locations
        locations = []
        for location_col in location_cols:
            try:
                v = row[location_col]
                if isinstance(v, str):
                    v = int(v, 16)
                locations.append(sarif_tools.physical_location(v))
            except ValueError:
                locations.append(sarif_tools.logical_location(row[location_col]))

        # Add to property bag and optionally specify it should be viewed on the Peach table
        prop_dict = {}
        for k, v in row[property_cols].to_dict().items():
            if k in table_cols:
                prop_dict[f'viewer/table/{k}'] = v
            else:
                prop_dict[k] = v

        properties = sarif_tools.property_bag_from_dict(prop_dict)
        result = sarif_tools.result(row[message_col],
                                    row[rule_id_col],
                                    locations=locations if len(locations) > 0 else None,
                                    properties=properties)
        results.append(result)
    run = sarif_tools.run(tool, results=results)
    log = sarif_tools.log([run])
    return log

def sha256sum(filename):
    ''' Get the sha256sum value of a file '''
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

def sarif_to_py(sarif_obj):
    ''' Convert sarif_om objs to json dumpable python objs '''
    if isinstance(sarif_obj, list):
        return [json.loads(sarif_to_json(o)) for o in sarif_obj]
    return json.loads(sarif_to_json(sarif_obj))

def load_sarif(fn):
    ''' json load a file '''
    return json.loads(Path(fn).read_text())

def write_sarif(sarif, filename):
    ''' Write the SarifLog to a file based on format its currently in '''
    # SarifLog -> string
    if isinstance(sarif, SarifLog):
        sarif = sarif_to_json(sarif)
    # String -> dict
    if isinstance(sarif, str):
        sarif = json.loads(sarif)

    # Sarif wants version and $schema first
    ordered_sarif = {
        'version': sarif['version'],
        '$schema': sarif['$schema']
    }
    for key in sarif.keys():
        ordered_sarif[key] = sarif[key]

    Path(filename).write_text(json.dumps(ordered_sarif, indent=2))

def get_url_branch_and_commit(path):
    ''' Get git information for version control objects '''
    path = Path(path)
    head_fn = path / '.git' / 'HEAD'
    config_fn = path / '.git' / 'config'
    if not (config_fn.exists() and head_fn.exists()):
        print('Unknown .git file structure')
        return None, None, None
    config = configparser.ConfigParser()
    config.read(config_fn)

    url = config['remote "origin"']['url']
    head_ref = path / '.git' / Path(head_fn.read_text().strip().split('ref: ')[1])
    branch = str(head_ref).split('refs/heads/')[1]
    commit = head_ref.read_text().strip()
    return url, branch, commit

def get_root_git(cwd):
    ''' Traverse up the directory structure to find if this belongs to a .git repository '''
    cwd = cwd.resolve()
    for path in [cwd, *cwd.parents]:
        if (path / '.git').exists():
            return path
    raise ValueError('No git found')
