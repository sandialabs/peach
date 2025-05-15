# Overview
A Ghidra module that serves as a SARIF viewer and a client to connect to a backend [Peach server](../server/README.md).

A tool could just output a sarif file and import into Ghidra through peach without utilizing the server.

## Installation
Either compile with Eclipse or use the distributed .zip
    - Can be installed either with File > Install Extensions or placing the extracted `Peach` directory into `$GHIDRA_HOME/Ghidra/Extensions`

See: `$GHIDRA_HOME/Extensions/Eclipse/GhidraDev/GhidraDev_README.html`

## Extending the Ghidra Module
- See Ghidra docs

# SARIF Viewer
The plugin, whether through `Peach > Read File` or through server communication will display a [SARIF File](https://sarifweb.azurewebsites.net/) as a Ghidra table. It will allow additional UI interactions if certain SARIF objects are present (e.g., Selection if a result has a CodeFlow, a Graph window if there is an embedded graph, or an image viewer if there are image artifacts).

To view the current set of SARIF features that are parsed see [SarifModel.java](Peach/src/main/java/peach/sarif/model/SarifModel.java#L53)
- Some SARIF objects provide additional interactions with the Ghidra UI such as:
    - [Result property bags](Peach/src/main/java/peach/sarif/model/SarifModel.java#L155)
    - [Taxonomies](Peach/src/main/java/peach/sarif/model/SarifModel.java#L143)
        - This includes [adding custom actions](Peach/src/main/java/peach/sarif/view/SarifResultsTableProvider.java#L80) on the result table.

See : [`Peach/src/main/java/peach/sarif`](Peach/src/main/java/peach/sarif)

# Peach Client
The client and server use a JSON-RPC-like communication, in order to remain stateless it uses a continuation passing style communication as well.
- These ultimately return a SARIF file to parse and display in the gui or a a simple notification to display.

- To add more to the API (feature/data extraction) look at `peach.api.PluginApiTask` as `peach.PeachPlugin.handleMethodCall` looks through that object for functions to call

See : [`Peach/src/main/java/peach/client`](Peach/src/main/java/peach/client)

## Server API
The server API is documented [here](Peach/src/main/java/peach/client/controller/PeachServerApi.java)

## Native API
The [native API](Peach/src/main/java/peach/client/controller/PeachAPI.java) utilizes strict typing and is better suited for direct use with a script or other plugin.

Example from the python interpreter:
``` python
from peach.client.controller.PeachAPI import getInstance

peachAPI = getInstance()
peachAPI.getCallGraph()
```
