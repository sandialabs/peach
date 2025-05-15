# Overview
Peach is a system to run and display custom analyses within Ghidra.

## Design goals
1. Offload custom analyses workloads to remote servers
2. Provide a standardized result display within Ghidra
3. Ease plugin and script development for common tasks

## 1. Offload custom analyses

The original design of Peach was to send data extracted from Ghidra to a remote server that was then capable of running Data Science workflows on the data and pass the results back for display.

This is accomplished through a [Ghidra plugin](client/README.md) and a [backend server](server/README.md).

## 2. SARIF viewer

In order to standardize how analyses would send results back to the Ghidra PeachPlugin, SARIF was adopted. Rather than needing to utilize the server/client architecture, the PeachPlugin can directly read a SARIF file and will attempt to display those results within Ghidra.

Any valid SARIF result file should be ingestable by Peach and provide a standard and custom interaction with the Ghidra UI.

See: [`client/README.md`](client/README.md)

## 3. Ease plugin and script development

By virtue of design goal 1 Peach extends Ghidra through two APIs that can be generically useful for any new script, and by virture of design goal 2 can faciliate creating plugin like fuctionality without as much overhead development.

### 1. Server API
This is a partial wrapper around the Native API to provide for generic (Strings) result and parameter types, to allow for JSON-RPC-like communication.

See: [`client/README.md`](client/README.md)
     [`server/README.md`](server/README.md)

### 2. Native API
This is an [extended API](client/README.md#native-api) (analogous to Ghidra's FlatProgramAPI) to faciliate common analysis workflows. While not directly called by the server, it can be directly called from any Ghidra scripts.

See: [`client/README.md`](client/README.md)
