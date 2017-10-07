!/bin/sh
sudo python3 CTR-ENC.py -k keyFile2 -i testFile3 -o ciphertext -v IV_1
sudo python3 CTR-DEC.py -k keyFile2 -i ciphertext -o message -v IV_1

vim -d testFile3 message
cmp testFile3 message
