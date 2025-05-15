''' Peach Defaults Plugin

A simple example of creating a server plugin for Peach.

Implements a few simple analyses.

The only function required is `get_methods`.
This should return a JSON object of analyses that the client can call.
These analyses should be encapsulated in a single function call specified by the JSON object.
'''
import inspect
import json
import time
import types
from importlib.resources import files
from importlib.util import find_spec
from inspect import signature
from pathlib import Path

import sarif_om

from peach.sarif_tools import *
from peach.utils import decode_file

try:
    import matplotlib.pyplot as plt
    import networkx as nx
except:
    pass

def get_methods(plugin_dir):
    ''' Get all analyses this plugin can do.

        These will be displayed as a list to the user to select.
        `method` is the function that will be called within this file.
        `params` are any additional arguments that the function would require '''
    methods = []

    methods.extend([
        # method names follow import naming
        {'method': 'defaults.example_options',
         'params': {
             # params naming should match the function parameters, because they will be called with **kwargs
             'string_set': ['one', 'two'], # A dropdown menu that selecs one
             'conf': { # a sliding scale, returns 1 value
                 'min': 0,
                 'max': 10,
                 'default': 2},
             'is_bool': 'true', # a checkbox
             'value': 'string'}}, # a freeform textbox
        {'method': 'defaults.func_decomp',
         'params': {
             'function': {
                 'method': 'peach.getAllFunctions', # Will call a function on the client and use its result
                 'params': [],
                 'show': 'true' # when `show` is true the result will be interpretted into a GUI element which the user can select
                 }}},
        {'method': 'defaults.binary_stats',
         'params': {
             'original_binary': {
                 'method': 'peach.dumpBinary',
                 'params': []}}} # will `show` false or not there the return value of the function will be passed here
        ])

    # If networkx is installed we can perform some analyses on graphs
    if find_spec('networkx') is not None and find_spec('matplotlib') is not None:
        # get functions from nx.community that only need one required argument (presumably the graph)
        community_algos = []
        for x in dir(nx.community):
            if isinstance(getattr(nx.community, x), types.FunctionType):
                parameters = signature(getattr(nx.community, x)).parameters.values()
                num_params = sum(p.default is inspect._empty for p in parameters)
                if num_params == 1:
                    community_algos.append(x)

        methods.extend([{'method': 'defaults.page_rank',
                         'params': {
                             'call_graph': {
                                 'method': 'peach.getCallGraph',
                                 'params': []}}},
                        {'method': 'defaults.community_detection',
                         'params': {
                             'algorithm':  community_algos,
                             'call_graph': {
                                 'method': 'peach.getCallGraph',
                                 'params': []}}},
                        {'method': 'defaults.reachable',
                         'params': {
                             'call_graph': {
                                 'method': 'peach.getCallGraph',
                                 'params': []},
                             'From Function': {
                                 'method': 'peach.getAllFunctions',
                                 'params': ['true'],
                                 'show': 'true'},
                             'To Function': {
                                 'method': 'peach.getAllFunctions',
                                 'params': ['true'],
                                 'show': 'true'}}}])
    return methods

def page_rank(call_graph, plugin_dir):
    ''' Compute the page rank on the function call graph.
    Returns the graph as both a SARIF graph object and an image artifact'''

    G = nx.to_networkx_graph(json.loads(call_graph)).to_directed()
    results = []
    for f, rank in nx.pagerank(G).items():
        results.append(logical_column(f.split(':')[0], 'function', rank, 'Page Rank'))
    plt.figure(figsize=(20,20))
    plt.title('Call Graph')
    nx.draw(G, with_labels=True)
    plt.savefig(plugin_dir / 'tmp.png')
    graph_artifact = artifact_file(plugin_dir / 'tmp.png', add_contents=True)
    thistool = tool('Peach page rank', '0.1', 'gitlab')
    return sarif_log(sarif_om.Run(thistool, graphs=[create_graph(G)], artifacts=[graph_artifact], results=results))

def community_detection(algorithm, call_graph, plugin_dir):
    ''' Community detection on the function call graph with the selected algorithm '''
    G = nx.to_networkx_graph(json.loads(call_graph)).to_directed()
    results = []
    community_func = getattr(nx.community, algorithm)
    for i, community in enumerate(community_func(G)):
        for f in community:
            results.append(logical_column(f.split(':')[0], 'function', i, 'Community ID'))
    thistool = tool('Peach community detection', '0.1', 'gitlab')
    return sarif_log(sarif_om.Run(thistool, results=results))

def reachable(**kwargs):
    ''' Indicated whether a function is reachable from another.
        Rather than returning a sarif object you can just send a pop-up '''
    call_graph, source, target = kwargs.get('call_graph'), kwargs.get('From Function'), kwargs.get('To Function')
    G = nx.to_networkx_graph(json.loads(call_graph)).to_directed()
    return {'notification': str(list(nx.shortest_path(G, source, target)))}

def example_options(string_set, conf, is_bool, value, plugin_dir):
    ''' A demonstration of possible parameters a plugin can request '''
    return {'notification': f'You selected: {string_set}, {conf}, {is_bool}, {value}'}

def func_decomp(function=None, decomp=None, plugin_dir=None):
    ''' Return a function's decomp.
        Demonstrates continuation passing '''

    if decomp is None:
    # The call specified by get_method only returns what function they want to decomp
    #    So we ask the client now for the decomp of the selected function, and pass forward the selected function
        results = {'method': 'defaults.func_decomp',
                   'params': {
                       'function': {'continuation': function.split(':')[0]}, # 'continuation' means just pass this as is back
                       'decomp': {
                           'method': 'peach.getDecomp',
                           'params': [function.split(': ')[1]]}}}
    else:
        # instead of sending a whole sarif file, just make a quick popup
        results = {'notification': f'{function}\n{decomp}'}
    return results

def binary_stats(original_binary, plugin_dir):
    ''' Computes some statistics on the binary '''
    import hashlib
    buf = decode_file(original_binary).getbuffer()
    h = hashlib.sha256()
    h.update(buf)
    return {'notification': f'Binary Size:{len(buf)}\nSha256:{h.hexdigest()}'}
