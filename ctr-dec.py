'''
Counter Mode decryption with AES cipher. 


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

def decrypt_worker(packet):
        C = packet[0]
        ctr = packet[1]
        key = packet[2]

        cipher = AES.AESCipher(key, AES.MODE_ECB)

        C_int = int.from_bytes(C, sys.byteorder)
        c = cipher.encrypt(ctr.to_bytes((ctr.bit_length()+7) // 8, 'big'))
        c_int = int.from_bytes(c, sys.byteorder)

        m_int = C_int ^ c_int

        return m_int.to_bytes((m_int.bit_length()+7) // 8, 'big')[::-1]

def decrypt(cypher_text, key):
        message = []
        packets = []
        p =Pool(5)
        ctr = cypher_text[0]
        cypher_text = cypher_text[1:]
        ctrs = [int.from_bytes(ctr, sys.byteorder) + i for i in range(len(cypher_text))]
        cipher = AES.AESCipher(key, AES.MODE_ECB)

        for C, ctr in zip(cypher_text, ctrs):
                packets.append((C, ctr, key))

        message = p.map(decrypt_worker, packets)
        return message

if __name__ == '__main__':
        args = get_args()
        infile = args['source']#"outfile"
        print(infile)
        outfile = args['output']#'outfile_r'
        print(outfile)
        keyfile = args['Key']#"data/temp/keyFile1"

        data = read(infile)
        key = read(keyfile)[0]

        C = decrypt(data, key)
        C = C
        write(C, outfile)
