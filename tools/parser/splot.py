import csv
import argparse
import os
import functools

# Constant

SERVERIP = '10.4.112.4'
SERVERIP_IN = '10.4.112.4'
#SERVERIP = '222.29.98'

TS = 'timestamp'
SOURCE = '_ws.col.Source'
DEST = '_ws.col.Destination'
RTT = 'tcp.analysis.ack_rtt'
BIF = 'tcp.analysis.bytes_in_flight'
LEN = 'tcp.len'
SEQ = 'tcp.seq'
FASTRETX = 'tcp.analysis.fast_retransmission'
TSVAL = 'tcp.options.timestamp.tsval'
TSECR = 'tcp.options.timestamp.tsecr'

RTTFN = '_rtt.txt'
RTTGN = 'rtt.eps'
BIFFN = '_bif.txt'
OOODFN = '_oood.txt'
OOODGN = 'oood.eps'
BIFGN = 'bif.eps'
THPFN = '_thp.txt'
THPGN = 'thp.eps'
RETXFN = '_retx.txt'
RETXGN = 'retx.eps'
LOSSFN = '_loss.txt'
LOSSGN = 'loss.eps'

# Core Function

def genLossFile(dataS, dataC, serverIP, fileName):
# Author: Jing
	f = open(fileName, 'w')
        sum = 0
        loss = 0
        keyTime = float(dataC[0][TS])
        
        client_list = [ (row[SEQ], row[TSVAL], row[TSECR]) for row in dataC ]

	for row in dataS:
		nowTime = float(row[TS])
		if row[SOURCE].find(serverIP) != -1:
			while nowTime - keyTime >= 1:
				if float(sum) > 0:
					f.write(str(keyTime) + " " + str(float(loss)/float(sum)*100) + '\n')
				sum = 0
				loss = 0
				keyTime = keyTime + 1
                        if (row[SEQ], row[TSVAL], row[TSECR]) in client_list:
				sum = sum + 1
                        else:
				sum = sum + 1
                                loss = loss + 1
	f.write(str(keyTime) + " " + str(float(loss)/float(sum)*100) + '\n')
	f.close()



def genRetxFile(dataS, serverIP, fileName):
	f = open(fileName, 'w')
	sent = set()
	for row in dataS:
		if row[SOURCE].find(serverIP) != -1 and row[LEN] != '' and row[LEN] != '0':
			if row[SEQ] in sent:
				f.write(row[TS] + ' 1\n')
			else:
				sent.add(row[SEQ])
			if row[FASTRETX] == '1':
				f.write(row[TS] + ' 2\n')
	f.close()

#def genFastRetxFile(dataS, serverIP, fileName):
#	f = open(fileName, 'w')
#	for row in dataS:
#		if row[SOURCE].find(serverIP) != -1 and row[LEN] != '' and row[LEN] != '0':
#			if row[FASTRETX] = '1':
#				f.write(row[TS] + ' 2\n')
#	f.close()

def genRttFile(dataS, serverIP, fileName):
	f = open(fileName, 'w')
	for row in dataS:
		if row[DEST].find(serverIP) != -1 and row[RTT] != '':
			f.write(row[TS] + ' ' + row[RTT] + '\n')
	f.close()

def genBifFile(dataS, serverIP, fileName):
	f = open(fileName, 'w')
	for row in dataS:
		if row[SOURCE].find(serverIP) != -1 and row[BIF] != '':
			f.write(row[TS] + ' ' + row[BIF] + '\n')
	f.close()

def genThpFile(dataC, serverIP, fileName):
	f = open(fileName, 'w')
	sum = 0
	keyTime = float(dataC[0][TS])
	for row in dataC:
		nowTime = float(row[TS])
		if row[SOURCE].find(serverIP) != -1:
			while nowTime - keyTime >= 1:
				f.write(str(keyTime) + " " + str(sum) + '\n')
				sum = 0
				keyTime = keyTime + 1
			try:
				sum = sum + int(row[LEN])
			except:
				sum = sum
	f.write(str(keyTime) + " " + str(sum) + '\n')
	f.close()

def genOoodFile(dataC, serverIP, fileName):

	def cmpS(x, y):
		t = int(y[SEQ]) - int(x[SEQ])
		if t < -2147483648:
			t = t + 4294967296
		if t > 2147483648:
			t = t - 4294967296
		if t > 0:
			return -1
		if t < 0:
			return 1
		if t == 0:
			return float(x[TS]) - float(y[TS])
	
	f = open(fileName, 'w')
	arr = []
	for row in dataC:
		if row[SOURCE].find(serverIP) != -1:
			arr.append(row)
	arr.sort(key = functools.cmp_to_key(cmpS))
	maxTime = 0
	for row in arr:
		if maxTime < float(row[TS]):
			maxTime = float(row[TS])
		f.write(str(maxTime) + " " + str(maxTime - float(row[TS])) + '\n')
	f.close()

# General Function

def loadCsv(fileName):
	arr = []
	data = csv.DictReader(open(fileName, 'r'))
	for row in data:
		arr.append(row)
	return arr

def gnuplotLines(targetFolder, noList, inFileSuffix, outFile, xText, yText, titleText):
	inputList = ''
	for no in noList:
		inputList = inputList + " " + targetFolder + no + inFileSuffix
	os.system('gnuplot -e \"inp=\'' + inputList +
		'\';outp=\'' + targetFolder + outFile +
		'\';xl=\'' + xText +
		'\';yl=\'' + yText +
		'\';ttl=\'' + titleText + '\'\" lib/lines.gp')

def gnuplotPoints(targetFolder, noList, inFileSuffix, outFile, xText, yText, titleText):
	inputList = ''
	for no in noList:
		inputList = inputList + " " + targetFolder + no + inFileSuffix
	os.system('gnuplot -e \"inp=\'' + inputList +
		'\';outp=\'' + targetFolder + outFile +
		'\';xl=\'' + xText +
		'\';yl=\'' + yText +
		'\';ttl=\'' + titleText + '\'\" lib/points.gp')

def gnuplotPointsEx(targetFolder, noList, inFileSuffix, outFile, xText, yText, titleText, ExCommand):
	inputList = ''
	for no in noList:
		inputList = inputList + " " + targetFolder + no + inFileSuffix
	os.system('gnuplot -e \"' + ExCommand + 'inp=\'' + inputList +
		'\';outp=\'' + targetFolder + outFile +
		'\';xl=\'' + xText +
		'\';yl=\'' + yText +
		'\';ttl=\'' + titleText + '\'\" lib/points.gp')

def plotAll(sourceFolder, targetFolder, serverIP, serverIP_in, noList):
	if sourceFolder[-1] != '/':
		sourceFolder = sourceFolder + '/'
	if targetFolder[-1] != '/':
		targetFolder = targetFolder + '/'
	for no in noList:
		dataS = loadCsv(sourceFolder + no + 's.csv')
		dataC = loadCsv(sourceFolder + no + 'c.csv')
		genRttFile(dataS, serverIP_in, targetFolder + no + RTTFN)
		#genBifFile(dataS, serverIP, targetFolder + no + BIFFN)
		genRetxFile(dataS, serverIP, targetFolder + no + RETXFN)
		genThpFile(dataC, serverIP, targetFolder + no + THPFN)
		genLossFile(dataS, dataC, serverIP_in, targetFolder + no + LOSSFN)
		#genOoodFile(dataC, serverIP, targetFolder + no + OOODFN)

	gnuplotLines(targetFolder, noList, RTTFN, RTTGN, 'Time (s)', 'RTT (s)', 'RTT Graph')
	#gnuplotLines(targetFolder, noList, BIFFN, BIFGN, 'Time (s)', 'Bytes in Flight (Bytes)', 'Bytes in Flight Graph')
	gnuplotLines(targetFolder, noList, THPFN, THPGN, 'Time (s)', 'Throughput (Bytes)', 'Throughput Graph')
	gnuplotLines(targetFolder, noList, LOSSFN, LOSSGN, 'Time (s)', 'Loss (100%)', 'Loss Graph')
	#gnuplotPoints(targetFolder, noList, OOODFN, OOODGN, 'Time (s)', 'Out-of-order Delay (s)', 'Out-of-order Delay Graph')
	gnuplotPointsEx(targetFolder, noList, RETXFN, RETXGN, 'Time (s)', 'Retransmission', 'Retransmission Graph', 'set yrange [0:4];')

# Main

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-s', '--source', type=str, help='Indicate name of the source folder.')
	parser.add_argument('-t', '--target', type=str, help='Indicate name of the target folder.')
	parser.add_argument('-i', '--ip', type=str, default=SERVERIP, help='Indicate IP of the server. Default = '+SERVERIP)
	parser.add_argument('-p', '--innerip', type=str, default=SERVERIP_IN, help='Indicate IP of the server. Default = '+SERVERIP_IN)
	parser.add_argument('-n', '--no', type=str, help='Indicate several NO.s whose corresponding traces would be analyzed simultaneously. Example: --no 1,2,3,4')
	args = parser.parse_args()
	plotAll(args.source, args.target, args.ip, args.innerip, args.no.split(','))
	
