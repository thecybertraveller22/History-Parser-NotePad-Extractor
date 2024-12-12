# Browsing History and Notepad Parser

By Muhammad Musaab 22i1560, Syed Arham Ahmed 22i1552, and some others.

# Description

Python 3 tool to fetch, compile, and view **all browsing data** and **unsaved Notepad++ tab content** on Windows 11\.

# Table of Contents

1. \[Installation\](\#installation)  
2. \[Usage\](\#usage)  
3. \[Features\](\#features)  
4. \[Testing\](\#testing)  
5. \[Contributing\](\#contributing)  
6. \[License\](\#license)  
7. \[Acknowledgements\](\#acknowledgements)

# Installation

On Windows 11, install the libraries `pywin32`, `sqlite3` and `cryptography` via:  
\`\`\`  
pip install cryptography  
pip install pywin32  
pip install sqlite3  
\`\`\`  
Then just move “**HistoryParser.py**” to a directory of your choice

# Usage

Simply run the “**HistoryParser.py**” file from *Command Prompt* by entering “**HistoryParser.py**” while in the directory of the file.  
From there you can choose to view either the *Notepad++* tab content or browsing data

# Features

## History Parser

- Fetch browsing data —including **bookmarks** and **saved passwords**— even while the browser is open/running (by making a copy of the browser’s history database file and reads)  
- Display hexadecimal+ASCII of **History file’s MBR** (Master Boot Record) as well as the History data itself  
- Supports **Chrome** as well as **Edge**

The tools for the browser data are semi-live — though the window content does not change as the corresponding browsing data changes, you can just click the button again to re-fetch the data.

In other words, the tool doesn't {fetch and store ALL data at once when “History Parser” is clicked, then just change according to the user's button-pressing which data is displayed in the window} —it fetches *the specific* data anew *each time* a button is clicked.

## Notepad++ Viewer

- Fetch all *Notepad++* tab content even while Notepad++ is open  
- Quickly updates in accordance with changes in content, just switch to History Parser by clicking the button and then back (no need to restart the application as a whole)  
- Show *Created time* and *Modified time*, and *Content Size* of the tabs

# Testing

May work on older versions of Windows, but only tested on Windows 11\.

# Contributing

Send money (in integer USDs) to help. Preferably contribute before our deadline

# License

This project is unlicensed as far as we know.

# Acknowledgements

Big thanks to OpenAI, as well as some team members.  
And for the Browsing Data Parser’s “Fetch Passwords” function specifically, an excellent team member of ours was generous enough to not just test on his own machine, but even *share* the results, which gave us ideas on how our tool may be modified to be part of an attack on a Windows machine.