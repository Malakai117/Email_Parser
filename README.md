Very basic Descriptions for now:

MyParser5.py: This is core of the program. all you need to do is get your api token from google for your gmail. the config file can be handled in the ui, unless using CLI.

rulemaker.py: This is essentially a library of function used to create and manage the config file. This is also CLI compatible, look at the argparse code for it's needs.

ParserUI.py: So far a simple ui using PySide6, and is used as the central control for all the scripts.
