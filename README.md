This small python utility is designed to create binaries with symbol tables for using during GDB 
debugging.

It allows you to take a stripped PE32 binary and a .MAP file exported from IDA (File->Produce File) 
and create a binary with debug symbols.

Usage:
./symbols.py <input PE32> <input MAP> <output BIN> 

e.g.
./symbols.py PE32.dll PE32.map PE32.bin
