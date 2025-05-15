# Overview
A forking JSON-RPC-like stateless TCP server.

This is a [namespace package](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/#using-namespace-packages) to allow server plugins to be installed.

A `defaults` plugin is provided as well to show an example and provide some simple useful analyses

## Installation
- `pip install .`
    - To install with networkx analyses in the defaults plugin `pip install .[GRAPH]`

## Usage
- `peach`
    - Will launch a server listening on `localhost:1124` and use a directory created through Python's TemporaryDirectory as an instance directory
    - `peach -h` will show help to change any of these options

# Developing a plugin
1. [Create and install](https://packaging.python.org/en/latest/guides/packaging-namespace-packages/) a package to the `peach.plugins` namespace.
    - e.g., create and install a package of the form `peach/plugins/<name>/__init__.py`
    - If you installed the `peach` package with `-e` you should be able to just place your plugin package in the `src/peach/plugins` directory (see the defaults plugin for example).
2. Implement `get_methods` within that package
    - This specifies what analyses your plugin can run.
        - This is displayed to the Ghidra user as a ComboBox selection.
    - Should accept a single parameter being a directory that is available to read and write to
    - should return a list of dictionaries with the following basic format:
        ``` python
        [
            {
                'method': '<plugin_name>.<function_name>',
            },
            {
                'method': '<plugin_name>.<function_name>',
                'params': {
                    '<paramName>': '<paramValue>',
                    ...
                }
            },
            {
                'method': '<plugin_name>.<function_name>',
                'params': ['<paramValue>', ...]
            },
            ...
        ]
        ```
        - `method` is a function that will be called when this analysis is selected.
        - `params` corresponds to the arguments needed for that function.
            - is optional and can be a list or an dictionary depending on if the function is called with positional or keyword arguments.
               - if it is a dictionary `paramName` is the keyword the argument is passed to 
            - `parameterValue` can be:
                - A string
                    - If the string is "true" or "false" a checkbox will be presented at the gui
                    - Otherwise will be textbox whose content is unverified client side
                - A list
                    - Will display as a ComboBox of each option as an item
                - A dict
                    - If it contains a `method` key
                        - `method` must be a [peach api](../client/README.md#server-api] function to call
                        - `params` must be a list of parameters to pass to the function
                            - The list can be empty
                        - if `show` key exists and is true
                            * e.g., ``` python
                                    {
                                        "method": "peach.getAllFunctions',
                                        "params": [],
                                        "show": "true"
                                    }
                                    ```
                            * Then the function is executed immediately and the result is reparsed as a `parameterValue` 
                        - Otherwise
                            * `method` and `params` follow the same rule but the function isn't executed until all options are selected and the return is passed back to the server plugin
                    - If it contains a `continuation` key
                        - the value in `continuation` is passed directly back to the server plugin
                            * Useful for when you has iterative option selection and need to pass forward selections from previous ones
                    - If it contains a `default` key
                        - Must contain keys "min" and "max" and create a slider value for these values
            - If all `parameterValues` are `"show": "false"` or `"continuation"` values (e.g., you are probably just calling peach ghidra module functions, then no options are displayed to the user before calling the server plugin
3. Implement any methods specified in `get_methods`
    - Should accept as the first parameter `plugin_dir` being a directory that is available to read and write to
    - These methods should return one of the following:
        1. A sarif log either in the format of a (json) string, dictionary, or `sarif_om.SarifLog` (see: `peach.sarif_tools`) for creating these log files
        2. A (json) string or dictionary with just a "notification" key where the value will be displayed in a dialog
        3. A (json) string or dictionary with a "method" get that follows the same format as an element in the list from `get_methods` which will display a new option window to interact with on the client
