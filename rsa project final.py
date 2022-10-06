#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 16 23:01:45 2022

"""

import random
import gc


###################
# generate a number#
###################
def generateNum():
    r = random.randint(2, 999)
    return r


################
# Tests if prime#
################
def testPrime(a):
    if a <= 1:
        return False
    else:
        for b in range(2, a):
            if a % b == 0:
                return False
    return True


#################
# Prime generator#
#################
def primeGen():
    r = generateNum()
    test = testPrime(r)
    while test == False:
        r = generateNum()
        test = testPrime(r)
    return r


############################
# tests gcd of two variables#
############################
def gcd(a=1, b=1):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


########
# find d#
########
def findD(a, b):
    if b == 0:
        return (1, 0, a)
    (x, y, d) = findD(b, a % b)
    return y, x - a // b * y, d


########
# find e#
########
def findE(phi):
    while True:
        e = random.randint(1, phi)
        if gcd(e, phi) == 1:
            break
    return e


#########################
# Encrypt with public key#
#########################
def encryptPublic(m, e, n):
    enmessage = pow(m, e, n)
    return enmessage


#############################
# Decryption with private key#
#############################
def decryptPrivate(m, d, n):
    demessage = pow(m, d, n)
    return demessage


######################
# Core Variable Values#
######################
def programValues(p, q, p1, q1, n, phi, e, d):
    message = 10
    encrypted = encryptPublic(message, e, n)
    decrypted = decryptPrivate(encrypted, d, n)
    print("q is", q)
    print("p is", p)
    print("n is", n)
    print("p1 is", p1)
    print("q1 is", q1)
    print("phi is", phi)
    print("e is", e)
    print("d is", d)
    print("example message is", message)
    print("example message encrypted is", encrypted)
    print("example message decrypted is", decrypted)


###################
# Encrypt a message#
###################
def encryptMsg(e, n):
    message = message = input("Please enter your message:")
    while bool(message) == False:
        print("Invalid input. Message cannot be empty!")
        message = input("Please enter your message:")
    message = convASCII(message)
    encryptMsg = ""
    i = 0
    a = 0
    while i < len(message):
        message[i] = encryptPublic(message[i], e, n)
        i = i + 1
    for a in message:
        encryptMsg = encryptMsg + chr(a)
    print("Your ciphertext is in Ascii: ", message)
    print("Your ciphertext is: ", str(encryptMsg))
    return message

###################
# Decrypt a message#
###################
def decryptMsg(ciphered, d, n):
    decryptedMsg = ciphered
    message = ""
    i = 0
    a = 0
    while i < len(decryptedMsg):
        decryptedMsg[i] = decryptPrivate(decryptedMsg[i], d, n)
        i = i + 1
    for a in decryptedMsg:
        message = message + chr(a)
    print("The decrypted message is in Ascii: ", decryptedMsg)
    print("The decrypted message is: ", str(message))

##########################
# Authenticate a signature#
##########################
def authSignature(signature, e, n):
    decryptedMsg = signature
    message = ""
    i = 0
    a = 0
    while i < len(decryptedMsg):
        decryptedMsg[i] = decryptPrivate(decryptedMsg[i], e, n)
        i = i + 1
    for a in decryptedMsg:
        message = message + chr(a)
    print("The digital signature decrypted message is in Ascii: ", decryptedMsg)
    print("The digital signature decrypted message is: ", str(message))


##############################
# Generate a digital signature#
##############################
def digSignature(d, n):
    message = input("Please enter your message:")
    while bool(message) == False:
        print("Invalid input. Message cannot be empty!")
        message = input("Please enter your message:")
    message = convASCII(message)
    signatureMsg = ""
    i = 0
    a = 0
    while i < len(message):
        message[i] = decryptPrivate(message[i], d, n)
        i = i + 1
    for a in message:
        signatureMsg = signatureMsg + chr(a)
    print("The message with the signature is in Ascii: ", message)
    print("The message with the signature is: ", str(signatureMsg))
    return message

##################
# Convert to ASCII#
##################
def convASCII(message):
    Ascii = []
    for character in message:
        Ascii.append(ord(character))
    return Ascii

#############
# public user#
#############
def publicUser(e, n, signature):
    while True:
        print("As a public user, what would you like to do?")
        print("\t1. Send an encrypted message.")
        print("\t2. Authenticate a digital signature.")
        print("\t3. Log out to previous menu.")
        choice = input("Enter your choice: ")
        if not choice.isdigit():
            print("Invalid choice!")
            continue
        choice = int(choice)
        if choice == 1:
            main.ciphered = encryptMsg(e, n)
            ciphered_lst.append(main.ciphered)
        elif choice == 2:
            if bool(signature) == False:
                print("Error: There isn't a digital signature to authenticate!")
            else:
                print("The following messages are available:")
                for i in range(len(signature_lst)):
                    print(f'{i + 1}. length = {len(signature_lst[i])}')
                choose = int(input("Enter your choice: "))
                authSignature(signature_lst[choose - 1], e, n)
        elif choice == 3:
            break

##############
# Private User#
##############
def ownerUser(d, n, ciphered):
    while True:
        print("As the owner of the keys, what would you like to do?")
        print("\t1. Decrypt a received message.")
        print("\t2. Digitally sign a message.")
        print("\t3. Log out to previous menu.")
        choice = input("Enter your choice: ")
        if not choice.isdigit():
            print("Invalid choice!")
            continue
        choice = int(choice)
        if choice == 1:
            if bool(ciphered) == False:
                print("Error: There isn't a message to decrypt!")
            else:
                print("The following messages are available:")
                for i in range(len(ciphered_lst)):
                    print(f'{i + 1}. length = {len(ciphered_lst[i])}')
                choose = int(input("Enter your choice: "))
                decryptMsg(ciphered_lst[choose - 1], d, n)
        elif choice == 2:
            main.signature = digSignature(d, n)
            signature_lst.append(main.signature)
        elif choice == 3:
            break
        ######


ciphered_lst = []
signature_lst = []
# main#
######
def main():

    main.ciphered = ""
    main.signature = ""
    p = primeGen()
    q = primeGen()
    p1 = p - 1
    q1 = q - 1
    n = p * q
    phi = p1 * q1
    e = findE(phi)
    d = findD(phi, e)[1]
    if d < 0: d += phi
    print("RSA keys have been generated.")
    while True:
        print("Please select your user type: ")
        print("\t1.A public user")
        print("\t2.The owner of the keys")
        print("\t3.Display core program values.")
        print("\t4.Exit program")
        choice = input("Enter your choice: ")
        if not choice.isdigit():
            print("Invalid choice!")
            continue
        choice = int(choice)
        if choice == 1:
            publicUser(e, n, main.signature)
        elif choice == 2:
            ownerUser(d, n, main.ciphered)
        elif choice == 3:
            programValues(p, q, p1, q1, n, phi, e, d)
        elif choice == 4:
            print("Bye for now!")
            gc.collect()
            break
        else:
            print("Invalid choice!\n")
main()