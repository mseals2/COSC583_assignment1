'''
Cipher Block Chained decryption with AES cipher. 
AKA game of types: Python edition 

Matt Seals: last revised 20171006 

'''
from Crypto.Cipher import AES
import sys

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


def decrypt(blocks, Key):

	plain_text = []
	cipher = AES.AESCipher(Key, AES.MODE_ECB)
	index = 0
	l = len(blocks)-1
	IV = blocks[0]

	for i in range(len(blocks))[1:]:
		txt = cipher.decrypt(blocks[i])
		r = int.from_bytes(txt, sys.byteorder) ^ int.from_bytes(IV, sys.byteorder)
		IV = blocks[i]
		plain_text.append(r.to_bytes((r.bit_length()+7) // 8, 'big')[::-1]) ##bytes are decryptted
																			#backward, this corrects it
	block_pad = plain_text[len(plain_text)-1]

	try :

		len_pad = block_pad[0] ## if pad is simply a cap pad of /x00's this will fail
		plain_text = plain_text[:len(plain_text)-1]
		plain_text[len(plain_text)-1] = plain_text[len(plain_text)-1][:16-len_pad]

	except: #case that the cypher text length could be evenly devided by 16

		plain_text = plain_text[:len(plain_text)-1]

	return plain_text
	

if __name__ == '__main__':

	args = get_args()
	source_file = args['source']
	key_file = args['Key']
	output = args['output']
	IV_file = args['IV']

	cypher_text = read(source_file)
	key = read(key_file)[0]
	C = decrypt(cypher_text, key)
	write(C, output)