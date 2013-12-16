# Fentanyl

## Introduction

Fentanyl is an IDAPython script that makes patching significantly easier. Fentanyl lets you patch from IDA Pro or Demo easily. Most patches can be done without touching a hex editor but if you must edit raw bytes you can simply use IDA's hex view. You can also undo and redo changes to the idb. 

## Setup

### IDAPython

 1. Download IDAPython [here](https://code.google.com/p/idapython/).
 2. Move appropriate folders to IDA plugins directory as per the `README`

### IDA PySide

 1. Download (custom built by ancat): Python 2.7 PySide bindings [here](https://drive.google.com/file/d/0ByZjdUcZD2dndng4Q1hrYWJiSUE/edit?usp=sharing).
 2. Extract and move PySide folder to `C:\python27\Lib\site-packages\`

## Usage

### Loading Fentanyl.py

1. `Alt+F7` or `File > Script File` to load scripts
2. Browse to `Fentanyl.py` and open it
3. That's hitlerally it!

### Key Bindings

*Some of these keybindings can be accessed by right-clicking on the screen in graph view.*

 * `Shift-N` Convert instructions to nops
 * `Shift-X` Nop all xrefs to this function
 * `Shift-J` Invert conditional jump
 * `Shift-U` Make jump unconditional
 * `Shift-P` Patch instruction
 * `Shift-Z` Undo modification (Won't always work. Should still be careful editing.)
 * `Shift-Y` Redo modification (Won't always work. Should still be careful editing.)
 * `Shift-S` Save file

## Extras

### Loading Fentanyl on Startup

Check out this [example](https://code.google.com/p/idapython/source/browse/trunk/examples/idapythonrc.py).

### PySide

PySide is a bitch to compile. If you don't want to use the PySide binaries available here, or don't want to compile it yourself, you don't actually need it. Fentanyl will not use the GUI if PySide is not available.
