def str2int(str_info):
	print('[**] strings: {0}'.format(str_info))
	int_info = int(str_info, 16)
	print('[**] hex: {0}'.format(hex(int_info)))
	return int_info

def bytes2int(bytes_info):
	print('[**] bytes: {0}'.format(bytes_info))
	int_info = int.from_bytes(bytes_info, byteorder='little')
	print('[**] hex: {0}'.format(hex(int_info)))
	return int_info
