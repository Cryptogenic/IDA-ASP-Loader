'''
IDA AMD PSP/ASP binary loader
@SpecterDev
'''
import binascii
import ida_idp
import idaapi
import idc
import struct

PSP_MAGIC_GENERIC               = 0x24505331 # $PS1
PSP_MAGIC_ABL_VARIANT_A         = 0x00424157 # [N]BAW
PSP_MAGIC_ABL_VARIANT_A_MASK    = 0xFF000000
PSP_MAGIC_ABL_VARIANT_A_SHIFT   = 24
PSP_MAGIC_ABL_VARIANT_B         = 0x41570042 # AW[N]B
PSP_MAGIC_ABL_VARIANT_B_MASK    = 0x0000FF00
PSP_MAGIC_ABL_VARIANT_B_SHIFT   = 8

def swap32(i):
	return struct.unpack("<I", struct.pack(">I", i))[0]

class PSPFile:
	def __init__(self, f):
		self.offset = f.tell()

		# 0x00-0x10
		f.seek(0x00)
		self.pad1 = struct.unpack("<16s", f.read(0x10))

		# 0x10-0x20
		f.seek(0x10)
		(self.magic, self.body_size, self.is_encrypted, self.pad2) = struct.unpack("<III4s", f.read(0x10))
		self.magic = swap32(self.magic)
		
		# 0x20-0x50
		f.seek(0x20)
		(self.iv, self.is_signed, self.pad3, self.signature_footprint, self.is_compressed, self.pad4) = struct.unpack("<16sI4s16sI4s", f.read(0x30))
		
		# 0x50-0x60
		f.seek(0x50)
		(self.uncompressed_size, self.zlib_size, self.pad5) = struct.unpack("<II8s", f.read(0x10))
		
		# 0x60-0x80
		f.seek(0x60)
		(self.version, self.pad6, self.load_addr, self.rom_size, self.pad7) = struct.unpack("<I4sII16s", f.read(0x20))
		
		# 0x80-0xA0
		f.seek(0x80)
		(self.wrapped_key, self.pad8) = struct.unpack("<16s16s", f.read(0x20))

		# 0xA0-0xA4
		f.seek(0xA0)
		self.abl_id = struct.unpack("<I", f.read(0x04))[0]
		self.abl_id = swap32(self.abl_id)

	def get_abl_num(self):
		if (self.magic == PSP_MAGIC_GENERIC):
			return (self.abl_id & PSP_MAGIC_ABL_VARIANT_B_MASK) >> PSP_MAGIC_ABL_VARIANT_B_SHIFT

		if (self.magic & ~PSP_MAGIC_ABL_VARIANT_A_MASK) == PSP_MAGIC_ABL_VARIANT_A:
			return (self.magic & PSP_MAGIC_ABL_VARIANT_A_MASK) >> PSP_MAGIC_ABL_VARIANT_A_SHIFT

		if (self.magic & ~PSP_MAGIC_ABL_VARIANT_B_MASK) == PSP_MAGIC_ABL_VARIANT_B:
			return (self.magic & PSP_MAGIC_ABL_VARIANT_B_MASK) >> PSP_MAGIC_ABL_VARIANT_B_SHIFT

	def is_abl0(self):
		abl_num = self.get_abl_num()

		if abl_num == 0x30:
			return True
		return False

	def is_abln(self):
		abl_num = self.get_abl_num()

		if abl_num >= 0x31 and abl_num <= 0x37:
			return True
		return False

def create_header_struct(address):
	pspStructId = idc.add_struc(-1, "PSPFileHeader", 0)

	idc.add_struc_member(pspStructId, "pad1", 0x00, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "magic", 0x10, idc.FF_STRLIT, -1, 0x04)
	idc.add_struc_member(pspStructId, "body_size", 0x14, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "is_encrypted", 0x18, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad2", 0x1C, idc.FF_BYTE, -1, 0x4)
	idc.add_struc_member(pspStructId, "iv", 0x20, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "is_signed", 0x30, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad3", 0x34, idc.FF_BYTE, -1, 0x04)
	idc.add_struc_member(pspStructId, "signature_footprint", 0x38, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "is_compressed", 0x48, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad4", 0x4C, idc.FF_BYTE, -1, 0x04)
	idc.add_struc_member(pspStructId, "uncompressed_size", 0x50, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "zlib_size", 0x54, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad5", 0x58, idc.FF_BYTE, -1, 0x08)
	idc.add_struc_member(pspStructId, "version", 0x60, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad6", 0x64, idc.FF_BYTE, -1, 0x04)
	idc.add_struc_member(pspStructId, "load_addr", 0x68, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "rom_size", 0x6C, idc.FF_DWORD, -1, 0x04)
	idc.add_struc_member(pspStructId, "pad7", 0x70, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "wrapped_key", 0x80, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "pad8", 0x90, idc.FF_BYTE, -1, 0x10)
	idc.add_struc_member(pspStructId, "abl_id", 0xA0, idc.FF_BYTE, -1, 0x04)

	idaapi.create_struct(address, 0x90, pspStructId)

def load_file(f, neflags, format):
	print('# ASP Loader')
	pspFile = PSPFile(f)

	idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER)
	idaapi.get_inf_structure().lflags |= idaapi.LFLG_PC_FLAT

	# Default addr of 0 (used for PSP_FW_BOOT_LOADER)
	address = 0x0

	# ABL0 standard addr is 0x15000, which seems to be the case when load addr is 0x100
	if pspFile.is_abl0():
		if pspFile.load_addr == 0x100:
			address = 0x15100
		else:
			# Exceptions, currently all we have is 4700s
			address = 0x54000

	# ABLN standard addr is 0x16200, which seems to be the case when load addr is 0x100
	if pspFile.is_abln():
		if pspFile.load_addr == 0x100:
			address = 0x16200
		else:
			# Exceptions, currently all we have is 4700s
			address = 0x57000 # for c09+

	end = address + 0x100
	
	print('# Creating header segment')
	idaapi.add_segm(0x0, address, end, 'HEADER', 'CONST', 0x0)
	f.seek(0x0)
	f.file2base(0x0, address, end, 0)

	create_header_struct(address)

	print('# Creating ROM Segment...')
	address += 0x100
	end = address + f.size() - 0x100

	idaapi.add_segm(0x0, address, end, 'ROM', 'CODE', 0x0)
	f.seek(0x100)
	f.file2base(0x100, address, end, 0)

	idaapi.add_entry(address, address, "start", 1)
	return 1

def accept_file(f, n):
	retval = 0

	print('# Checking for ASP')

	f.seek(0)
	pspFile = PSPFile(f)

	if pspFile.magic == PSP_MAGIC_GENERIC or (pspFile.magic & ~PSP_MAGIC_ABL_VARIANT_A_MASK) == PSP_MAGIC_ABL_VARIANT_A or (pspFile.magic & ~PSP_MAGIC_ABL_VARIANT_B_MASK) == PSP_MAGIC_ABL_VARIANT_B:
		retval = "AMD-SP Firmware Blob"
		magicStr = bytearray.fromhex('{:x}'.format(pspFile.magic)).decode()

		print('# PSP File found!')
		print('# Magic: {:s}'.format(magicStr))
		print('# Version: {:02x}'.format(pspFile.version))
		print('# Is encrypted: {}'.format(pspFile.is_encrypted))
		print('# Is signed: {}'.format(pspFile.is_signed))
		print('# Is compressed: {}'.format(pspFile.is_compressed))
		print('# Load Address: 0x{:02x}'.format(pspFile.load_addr))
		print('# ROM size: 0x{:02x}'.format(pspFile.rom_size))
		print('# Body size: 0x{:02x}'.format(pspFile.body_size))
		print('# Zlib size: 0x{:02x}'.format(pspFile.zlib_size))
		print('# Uncompressed size: 0x{:02x}'.format(pspFile.uncompressed_size))
		print('# Wrapped key: {}'.format(binascii.hexlify(pspFile.wrapped_key, ' ').decode()))
		print('# IV: {}'.format(binascii.hexlify(pspFile.iv, ' ').decode()))
		print('# Signature footprint: {}'.format(binascii.hexlify(pspFile.signature_footprint, ' ').decode()))
		print('# ABL ID: {}'.format(pspFile.abl_id))

	return retval
