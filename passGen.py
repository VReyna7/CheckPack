import random as rd 
import string as str 

def pass_gen():
    letters = str.ascii_letters + str.digits + str.punctuation
    password = ''.join(rd.choice(letters) for x in range(12))
    return password