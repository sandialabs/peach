''' A command line tool for logging information in a SARIF log file. '''

import argparse
import datetime
from pathlib import Path

import sarif_om
from jschema_to_python.to_json import to_json as sarif_to_json

from .om_wrapper import (artifact_file, create_invocation, property_bag,
                         sarif_log, tool, version_control)
from .utils import (file_to_sarif, get_url_branch_and_commit, load_sarif,
                    sarif_to_py, sha256sum, write_sarif)


def parse_args(args=None, append_logfile=False):
    parser = argparse.ArgumentParser(description='Run a command and do your best to save information in sarif log file.')
    parser.add_argument('-n', '--dry-run', action='store_false', help="Don't run the command just output a log file based on this")
    parser.add_argument('-a', '--artifact', action='append', help='Add artifact information for this file.', default=[])
    parser.add_argument('-c', '--artifact_content', action='append', help='Add artifact information and content for this file', default=[])
    parser.add_argument('-g', '--git', action='append', help='Add git information from this path.', default=[])
    parser.add_argument('--comment', help='Comment to add to tool run')
    if append_logfile:
        parser.add_argument('logfile', help='logfile to append to.')
    else:
        parser.add_argument('-o', '--outfile', help='logfile path to save.')
        parser.add_argument('--capture', action='store_true', help='capture stdout and stderr into log.')
        parser.add_argument('cmd', nargs=argparse.REMAINDER)
    # parser.add_argument('-t', '--trace', action='store_true', help='do strace or stat files or something to auto get artifacts')
    return parser.parse_args(args)

def parse_convert_args(args=None):
    parser = argparse.ArgumentParser(description='Convert a file to a SARIF log.')
    parser.add_argument('filename', help='Path of file to convert.')
    parser.add_argument('-t', '--table_cols', action='extend', nargs='+', type=str, help="Columns to display on table.")
    parser.add_argument('-m', '--message_col', type=str, help="Column to use as result message.")
    parser.add_argument('-i', '--rule_id_col', type=str, help="Column to use as result rule_id.")
    parser.add_argument('-l', '--location_cols', action='extend', nargs='+', type=str, help="Column to use as result location.")
    parser.add_argument('-o', '--outfile', help='Path to output new sarif to. Defaults to changing the suffix of the file to ".sarif"')

    return parser.parse_args(args)

def run_convert():
    args = parse_convert_args()
    log = file_to_sarif(args.filename,
                        message_col=args.message_col,
                        rule_id_col=args.rule_id_col,
                        table_cols=args.table_cols,
                        location_cols=args.location_cols)
    outfile = args.outfile
    if not outfile:
        outfile = Path(args.filename).with_suffix('.sarif')
    write_sarif(log, outfile)

def run_log_command():
    args = parse_args()
    log_command(
        args.cmd,
        args.git,
        args.artifact,
        args.artifact_content,
        args.outfile,
        comment=args.comment,
        do_run=args.dry_run,
        capture=args.capture
    )

def run_append_info():
    args = parse_args(append_logfile=True)
    append(
        args.git,
        args.artifact,
        args.artifact_content,
        args.logfile,
        comment=args.comment,
    )

def run_read_log():
    parser = argparse.ArgumentParser(description='Read a sarif log file and display stuff.')
    parser.add_argument('logfile', help='logfile to read.')
    args = parser.parse_args()
    log = load_sarif(args.logfile)
    runs = log.get('runs', [])
    for run in runs:
        print(f"Run: {run['tool']['driver']['name']}")
        print_invocations(run)
        print_artifacts(run)
        print_version_control(run)


def print_invocations(run):
    invocations = run.get('invocations', [])
    for invocation in invocations:
        print(f"\tCommand: {invocation['commandLine']}")
        if 'endTimeUtc' in invocation:
            start = datetime.datetime.fromisoformat(invocation['startTimeUtc'])
            end   = datetime.datetime.fromisoformat(invocation['endTimeUtc'])
            print(f'\tElapsed time: {end-start}')
        properties = invocation.get('properties', {})
        if 'stdout' in properties:
            print('\tstdout:')
            for line in properties['stdout'].splitlines():
                print(f'\t\t{line}')

        if 'stderr' in properties:
            print('\tstderr:')
            for line in properties['stderr'].splitlines():
                print(f'\t\t{line}')

def print_artifacts(run):
    artifacts = run.get('artifacts', [])
    if len(artifacts) > 0:
        print("\tArtifacts:")
    for artifact in artifacts:
        fn = Path(artifact['location']['uri'])
        if not fn.exists():
            print(f'\t\t{str(fn)}: Does not exist')
        elif 'hashes' in artifact:
            if sha256sum(fn) == artifact['hashes']['sha-256']:
                print(f'\t\t{str(fn)}: Hashes match')
            else:
                print(f'\t\t{str(fn)}: Error hashes mismatch')
        else:
            print(f'\t\t{str(fn)}: No hash found')

def print_version_control(run):
    ''' Get version control information '''
    provenance = run.get('versionControlProvenance', [])
    if len(provenance) > 0:
        print('\tVersion Control Provenance')
    for vc in provenance:
        if vc is None:
            continue
        mapped_path = vc['mappedTo']['uriBaseId']
        _, branch, commit = get_url_branch_and_commit(mapped_path)
        print(f'\t\t{vc["repositoryUri"]}')
        if branch:
            print(f'\t\t\tChecked out at: {mapped_path}')
            branch_match = ': Same branch' if vc['branch'] == branch else ': Different branch checked out'
            commit_match = ': Same commit' if vc['revisionId'] == commit else ': Different commit checked out'
        else:
            print(f'\t\t\tNot checked out at: {mapped_path}')
            branch_match = ''
            commit_match = ''
        print(f'\t\t\t\tBranch: {vc["branch"]}{branch_match}')
        print(f'\t\t\t\tCommit: {vc["revisionId"]}{commit_match}')

def log_command(cmd, git, artifact, artifact_content, outfile, comment=None, do_run=False, capture=False):
    ''' Log a command run. Like for a data pipeline
    Parameters
    ----------
    cmd: list
        command to pass to subprocess
    git: list
        list of paths to add as version control provenance elements
    artifact: list
        list of paths to add as artifacts without content
    artifact_content: list
        list of paths to add as artifacts with content
    outfile: str
        path to write log (or append if exists this run) to
    do_run: bool
        whether to actually run the command
    '''
    t  = tool(cmd[0], '', '')
    i  = create_invocation(cmdline=cmd, do_run=do_run, capture=capture)

    vcs = []
    for g in git:
        vcs.append(version_control(g))
    vcs = [vc for vc in vcs if vc]

    artifacts = []
    for part in cmd:
        if Path(part).exists():
            artifacts.append(artifact_file(part))
    for a in artifact:
        artifacts.append(artifact_file(a))
    for c in artifact_content:
        artifacts.append(artifact_file(c, add_contents=True))

    r = sarif_om.Run(
            t,
            invocations=[i],
            artifacts=artifacts if len(artifacts) > 0 else None,
            version_control_provenance=vcs if len(vcs) > 0 else None
    )

    out_fn = outfile
    if out_fn is None:
        now = datetime.datetime.utcnow().isoformat()
        out_fn = Path(f'{now}-{cmd[0]}.sarif')
    else:
        out_fn = Path(outfile)

    if out_fn.exists():
        append_to_log(out_fn, runs=r)
    else:
        log = sarif_log(r, properties=property_bag(comment=comment))
        out_fn.write_text(sarif_to_json(log))

def append(git, artifact, artifact_content, logfile, comment):
    ''' Append run information to an existing logfile '''
    vcs = []
    for g in git:
        vcs.append(version_control(g))

    artifacts = []
    for a in artifact:
        artifacts.append(artifact_file(a))
    for c in artifact_content:
        artifacts.append(artifact_file(c, add_contents=True))

    append_to_log(
        logfile,
        artifacts=artifacts if len(artifacts) > 0 else None,
        version_control_provenance=vcs if len(vcs) > 0 else None,
        log_comment=comment
    )

def append_to_log(sarif_fn, runs=None, log_comment=None,
                  run_comment=None, artifacts=None,
                  version_control_provenance=None, run_idx=-1):
    ''' Add stuff to an existing log file, either run information or more runs '''
    log = load_sarif(sarif_fn)

    if artifacts is not None:
        if not isinstance(artifacts, list):
            artifacts = [artifacts]
        artifacts = sarif_to_py(artifacts)
        run = log['runs'][run_idx]
        if 'artifacts' not in run:
            run['artifacts'] = artifacts
        else:
            run['artifacts'].extend(artifacts)

    if version_control_provenance is not None:
        if not isinstance(version_control_provenance, list):
            version_control_provenance = [version_control_provenance]
        version_control_provenance = sarif_to_py(version_control_provenance)
        run = log['runs'][run_idx]
        if 'versionControlProvenance' not in run:
            run['versionControlProvenance'] = version_control_provenance
        else:
            run['versionControlProvenance'].extend(version_control_provenance)

    if log_comment is not None:
        if 'properties' not in log:
            log['properties'] = {}
        if 'comment' not in log['properties']:
            log['properties']['comment'] = log_comment
        else:
            log['properties']['comment'] += log_comment

    if run_comment is not None:
        run = log['runs'][run_idx]
        if 'properties' not in run:
            run['properties'] = {}
        if 'comment' not in run['properties']:
            run['properties']['comment'] = run_comment
        else:
            run['properties']['comment'] += run_comment

    if runs is not None:
        if not isinstance(runs, list):
            runs = [runs]
        runs = sarif_to_py(runs)
        log['runs'].extend(runs)

    write_sarif(log, sarif_fn)
