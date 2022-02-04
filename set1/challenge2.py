inputA = bytes.fromhex('1c0111001f010100061a024b53535009181c')
inputB = bytes.fromhex('686974207468652062756c6c277320657965')

output = bytes(byteA ^ byteB for (byteA, byteB) in zip(inputA, inputB))
print(output.hex())