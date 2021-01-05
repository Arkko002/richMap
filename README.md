RichMap
=======
[![Build Status](https://travis-ci.org/Arkko002/richMap.svg?branch=master)](https://travis-ci.org/Arkko002/richMap)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Port scanner, banner grabber and live host discovered written in Python.

## Table of Contents
1. [Table of Contents](#table-of-contents)
2. [Screenshots](#screenshots)
3. [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation](#installation)
4. [Usage](#usage)
    * [Examples](#examples)
5. [Documentation](#documentation)

### Screenshots
!TODO update

![alt text](https://i.imgur.com/UxDr9FN.png)
- *CLI*

![alt text](https://i.imgur.com/h6Ef8f1.png)
- *GUI with high verbosity*

## Getting Started
### Prerequisites
RichMap uses raw sockets for most of the scanning techniques which means it requires root privileges to access full
functionality, although `TCP scan` and `Ping discovery` can be used without root.

### Installation
Latest version of RichMap is hosted on PyPI. You can install it with:

```pip install -g richmap```

This will install RichMap globally.

## Usage
RichMap is split into port scanning and host discovering components, which can be accessed
respectively with `scan` and `discover`.

To view quick help for either of them pass an `-h` flag to the command.

### Examples
ACK scan on a target with port range:
```
scan -sA -t 192.168.0.1 -p 1-1024
```

Ping scan with default port range:
```
scan -sP -t 192.168.0.1
```

ARP host discovery:
```
discover -mA -t 192.168.0.0/24
```

## Documentation
!TODO