import random
import hashlib

abcSet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+"
length = random.randint(10, 1024)
abc = ""
for i in range(length):
    abc += abcSet[random.randint(0, 74)]

print(abc)
print("length: ", length)
print("sha256: ", hashlib.sha256(abc.encode("ascii")).hexdigest())
