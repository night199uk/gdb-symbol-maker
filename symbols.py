#!/usr/bin/python
import re
import sys
import pefile
import struct
import binascii
import subprocess

class Symbol(object):
	def __init__(self, sec, offset, name):
		self.sec = sec
		self.offset = offset
		self.name = name

class Section(object):
	def __init__(self, offset, length, name, kind):
		self.offset = offset
		self.length = length
		self.name = name
		self.kind = kind

pefilename = sys.argv[1]
symbolfilename = sys.argv[2]
outputfilename = sys.argv[3]

image_base = None
sections = []
symbols = []

pe = pefile.PE(pefilename)
image_base = pe.OPTIONAL_HEADER.ImageBase
for section in pe.sections:
	offset = section.VirtualAddress
	length = section.Misc_VirtualSize
	name = section.Name.strip('\x00')
	kind = section.Characteristics
	if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
		kind = "CODE"
	else:
		kind = "DATA"
	sections.append(Section(offset, length, name, kind))

section = Section(0x0, sections[0].offset, "HEADER", "DATA")
sections.insert(1, section)

file = open(symbolfilename, "r")
for line in file.readlines():

	### Section
	### Does not work as IDA output is broken. Get from the PE directly instead.
#	m = re.match("^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)H\s+([^s]*)\s+(CODE|DATA)\s*$", line)
#	if m:
#		sec = m.group(1)
#		offset = m.group(2)
#		length = m.group(3)
#		name = m.group(4)
#		kind = m.group(5)
#
#		sec = int(sec, 16)
#		offset = int(offset, 16)
#		length = int(length, 16)
#

	### Symbol
	m = re.match("^\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+([^\s]+)\s*$", line)
	if m:
		sec = m.group(1)
		offset = m.group(2)
		name = m.group(3)

		sec = int(sec, 16)
		sec = sections[sec - 1]
		if sec.name == "HEADER" or sec.name == ".reloc":
			continue

		offset, = struct.unpack('>q', binascii.unhexlify(offset))
		if offset < 0:
			offset = sec.offset + sec.length + offset

		symbol = Symbol(sec, offset, name)
		symbols.append(symbol)

file.close()

#sorted_sections = sorted(sections, key = lambda k: k.offset)
#for section in sorted_sections:
#	print("offset: 0x{0:x} length: 0x{1:x} name: {2!s} kind: {3!s}".format(section.offset, section.length, section.name, section.kind))

sorted_symbols = sorted(symbols, key = lambda k: k.offset)

last_address = 0x0
file = open("/tmp/gdbtab.s", "w")
for symbol in sorted_symbols:
	file.write('.space {},0x90\n'.format((symbol.sec.offset + symbol.offset) - last_address))
	file.write('.global \"{}\"\n'.format(symbol.name))
	file.write(' \"{}\":\n'.format(symbol.name))
	last_address = symbol.sec.offset + symbol.offset
file.write('.p2align 12'.format(symbol.name))
file.close()

### Mac
popen = subprocess.Popen(("/usr/bin/as", "-arch", "x86_64", "/tmp/gdbtab.s", "-o", "/tmp/gdbtab.o"), stdout=subprocess.PIPE)
popen.wait()
output = popen.stdout.read()
print(output)

popen = subprocess.Popen(("ld", "-arch", "x86_64", "-macosx_version_min", "10.10", "-dylib", "-image_base", '0x{:x}'.format(image_base), "-o", outputfilename, "/tmp/gdbtab.o"), stdout=subprocess.PIPE)
popen.wait()
output = popen.stdout.read()
print(output)

### Linux (untested)
#popen = subprocess.Popen(("gcc", "-Wl,-N,-Ttext,$base", "-nostdlib", "-o",  outputfilename, "/tmp/gdbtab.s"), stdout=subprocess.PIPE)