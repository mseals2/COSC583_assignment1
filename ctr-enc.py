'''
Counter Mode encryption with AES cipher. 
AKA game of types II Electric Boogaloo: A return to innocence

Matt Seals: last revised 20171006 


'''




from Crypto.Cipher import AES
import sys
from multiprocessing import Pool


def get_args():

        args = {}
        for i in range(len(sys.argv)):
                if(sys.argv[i] == '-k'):
                        args['Key'] = sys.argv[i + 1]

                if(sys.argv[i] == '-i'):
                        args['source'] = sys.argv[i + 1]

                if(sys.argv[i] == '-o'):
                        args['output'] = sys.argv[i + 1]

                if(sys.argv[i] == '-v'):
                        args['IV'] = sys.argv[i + 1]
        return args



def read(name):
	f = open(name, 'rb')
	text = f.read()
	n = 16
	blocks = [text[i:i+n] for i in range(0, len(text), n)]
	return blocks


def write(data, name):
	f = open(name, 'wb')
	for d in data:
		f.write(d)


def encrypt_worker(pac):
	ctr = pac[1]
	key = pac[2][:16]
	m = pac[0]
	cipher = AES.AESCipher(key, AES.MODE_ECB)
	m_int = int.from_bytes(m, sys.byteorder)
	a = ctr.to_bytes((ctr.bit_length() +7 ) // 8, 'big')
	c = cipher.encrypt(a)
	c_int = int.from_bytes(c, sys.byteorder)

	return c_int, m_int

def encrypt(text, counter, key):
	cypher_text = []
	packets = []
	p = Pool(5)
	ctrs = [int.from_bytes(counter, sys.byteorder) + i for i in range(len(text))]
	cypher_text.append(counter)
	cipher = AES.AESCipher(key, AES.MODE_ECB)

	packets = [(m, ctr, key) for ctr ,m in zip(ctrs, text)]
	
	X = p.map(encrypt_worker, packets)

	'''
		normally the XORing would be done in the threaded process, but for some reason when you 
		do the following in 'encrypt_workder' it returns a diffrent value that results 
		in an incorrect encryption/decryption. 

	'''

	for x in X:
		i = x[0] ^ x[1]   
		cypher_text.append(i.to_bytes(16, sys.byteorder))

	return cypher_text

if __name__ == '__main__':
	args = get_args()
	infile = args['source'] #"data/temp/testFile1"
	outfile = args['output']#'outfile'
	keyfile = args['Key'] #"data/temp/keyFile1"
	ctr_file = args['IV']#'abcdefg012345678'

	data = read(infile)
	#data = pad(data)
	ctr = read(ctr_file)[0]
	key = read(keyfile)[0]

	C = encrypt(data, ctr, key)
	write(C, outfile)
