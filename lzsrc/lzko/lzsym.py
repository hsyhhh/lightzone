import sys

f_lzsym = open("arch/arm64/lzsym.h", 'r')
f_sysmap = open("../../kbuild/System.map", 'r')
if sys.argv[1] == "board":
	print("Building the kernel module for the board!")
	f_sysmap.close()
	f_sysmap = open("../../board/Linux_for_Tegra/source/public/kernel/kbuild/System.map", 'r')

lines = f_lzsym.readlines()
sysmap_lines = f_sysmap.readlines()

for i in range(len(lines)):
	line = lines[i]
	pos = line.find('#define IMPORT_SYMBOL_VALUE_FOR_')
	if pos != -1:
		line = line[len('#define IMPORT_SYMBOL_VALUE_FOR_'):]
		symbol = line[:line.find('\t')]
		value = ''

		# fine symbol in System.map
		for sysmap_line in sysmap_lines:
			symbol_pos = sysmap_line.find(symbol)
			if symbol_pos != 0:
				if sysmap_line[symbol_pos - 1] != ' ':
					continue
			if symbol_pos != -1:
				# make sure whole word match
				if symbol_pos + len(symbol) + 1 != len(sysmap_line):
					continue
				value = sysmap_line[:sysmap_line.find(' ')]
				break
		# print(symbol, value)

		pos1 = line.find('(')
		pos2 = line.find(')')
		# print(line[pos1+1:pos2])

		if value == '':
			value = '0'

		lines[i] = '#define IMPORT_SYMBOL_VALUE_FOR_' + line[:pos1] + '(0x' + value + 'UL)\n'

f_lzsym.close()

f_lzsym = open("arch/arm64/lzsym.h", 'w')

for line in lines:
	f_lzsym.write(line)

f_lzsym.close()
f_sysmap.close()

