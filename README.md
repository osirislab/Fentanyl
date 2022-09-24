# Fentanyl

## Introduction

Fentanyl is an IDAPython script that makes patching significantly easier. Fentanyl lets you patch from IDA Pro or Demo easily. Most patches can be done without touching a hex editor but if you must edit raw bytes you can simply use IDA's hex view. You can also undo and redo changes to the idb. 

Fentanyl supercedes other tools for binary patching by being able to assemble with IDA's built in assemblers which can support more than x86 and x86_64. Fentanyl also automates commonly performed patches. One of Fentanyl's best features is that it supports Undo/Redo. We can see changes to the graph live and undo them if they aren't to our liking. 

<img width=75% height=75% src="http://blog.isis.poly.edu/images/2014/03/assemble2.gif">

## Setup (IDA 7.x / Python 3)

Simply move all items from this repository into the following directory:

```
%IDA%\plugins
```

The `%IDA%` directory can usually be found bellow:

```
C:\Program Files\IDA <version>\
```

Now on program start, the plugin will be loaded automatically.

## Setup (IDA 6.x / Python 2)

```
Need to add backwards compatibility with IDA 6.x or mark as deprecated
```
### IDAPython

 1. Download IDAPython [here](https://code.google.com/p/idapython/).
 2. Move appropriate folders to IDA plugins directory as per the `README`

### IDA PySide

 1. Download (custom built by ancat): Python 2.7 PySide bindings [installer](https://drive.google.com/file/d/0ByZjdUcZD2dnQkw4cHU1bmZzWE0/edit?usp=sharing) or [raw](https://drive.google.com/file/d/0ByZjdUcZD2dndng4Q1hrYWJiSUE/edit?usp=sharing).
 2. Extract and move PySide folder to `C:\python27\Lib\site-packages\`

## Usage

### Loading Fentanyl.py

#### IDA 7.x / Python 3

Follow instructions under Setup.

#### IDA 6.x / Python 2
1. `Alt+F7` or `File > Script File` to load scripts
2. Browse to `main.py` and open it
3. That's it!

### Key Bindings

*Some of these keybindings can be accessed by right-clicking on the screen in graph view.*

 * `Ctrl-Alt-N` Convert instructions to nops
 * `Ctrl-Alt-X` Nop all xrefs to this function
 * `Ctrl-Alt-J` Invert conditional jump
 * `Ctrl-Alt-P` Patch instruction
 * `Alt-Z` Undo modification (Won't always work. Should still be careful editing.)
 * `Alt-Y` Redo modification (Won't always work. Should still be careful editing.)
 * `Ctrl-Alt-S` Save file
 * `Ctrl-Alt-C` Find Code Caves
 * `Ctrl-Alt-F` Make jump unconditional
 * `Ctrl-Alt-N` Neuter the binary (remove calls to fork, setuid, setgid, getpwnam, setgroups, and chdir)

## Extras

### Loading Fentanyl on Startup

Check out this [example](https://code.google.com/p/idapython/source/browse/trunk/examples/idapythonrc.py).

### PySide

PySide is annoying to compile. If you don't want to use the PySide binaries available here, or don't want to compile it yourself, you don't actually need it. Fentanyl will not use the GUI if PySide is not available.
