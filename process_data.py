with open('output.txt', 'r') as f:
    a = f.read()
a = bytes.fromhex(a)
chunks = [a[i:i+4] for i in range(0, len(a), 4)]

part4 = [chunk[::-1] for chunk in chunks]
a = b''.join(part4)

with open('final_bytes', 'wb') as f:
    f.write(a)