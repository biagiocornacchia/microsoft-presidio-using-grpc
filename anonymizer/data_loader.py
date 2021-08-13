import anonymizer_client as anonymizer
import os
from os import system, name
import time
import sys

def presidio_anonymizer_start(clientAnonymizer):
    
    print("SERVER INFO: {}:{}".format(clientAnonymizer.ip_address, clientAnonymizer.port))

    while True:
        print("\n1) Setup config file")
        print("2) Read the current config")
        print("3) Start anonymization")
        print("4) Back")

        command = int(input("\nCommand: "))

        if command == 1:            
            setupConfig(clientAnonymizer, anonymizer.CONFIG_FILE)
            clear()
        elif command == 2:       
            if not clientAnonymizer.readConfiguration(anonymizer.CONFIG_FILE):
                print("Configuration file not found!")

            exit()
        elif command == 3:
            filenameList = []

            numFiles = int(input("\nHow many files do you want to anonymize? "))

            for i in range(numFiles):
                filenameList.append(input("{}) Filename: ".format(i+1)))

            for filename in filenameList:
                print("\n=============== {} ANONYMIZATION ===============\n".format(filename))
                
                if clientAnonymizer.sendRequestAnonymize(filename) != -1:
                    print("\n{} anonmized successfully!\n".format(filename))
                else:
                    print("\nFile missing for {}!\n".format(filename))

            exit()
        elif command == 4:
            break
        else:
            print("\nCommand not valid!")

def presidio_deanonymizer_start(clientAnonymizer):
 
    print("SERVER INFO:  {}:{}".format(clientAnonymizer.ip_address, clientAnonymizer.port))

    while True:
        print("\n1) Setup config file")
        print("2) Read the current config")
        print("3) Start deanonymization")
        print("4) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            setupConfig(clientAnonymizer, anonymizer.CONFIG_FILE_DE)
            clear()
        elif command == 2:
            if not clientAnonymizer.readConfiguration(anonymizer.CONFIG_FILE_DE):
                print("Configuration file not found!")

            exit()
        elif command == 3:
            filenameList = []

            numFiles = int(input("\nHow many files do you want to anonymize? "))

            for i in range(numFiles):
                filenameList.append(input("{}) Filename (ex. filename-anonymized): ".format(i+1)))

            for filename in filenameList:
                print("\n=============== {} DEANONYMIZATION ===============\n".format(filename))
                
                if clientAnonymizer.sendRequestDeanonymize(filename) != -1:
                    print("\n{} deanonmized successfully!\n".format(filename))
                else:
                    print("\nFile missing for {}!\n".format(filename))

            exit()

        elif command == 4:
            break
        else:
            print("\nCommand not valid!")

def setupConfig(clientAnonymizer, configFile):
    
    if configFile == anonymizer.CONFIG_FILE:
        configType = "Anonymizer"
    elif configFile == anonymizer.CONFIG_FILE_DE:
        configType = "Deanonymizer"
    else:
        print("ERROR: configuration file not valid!")

    if os.path.exists(configFile):
        print("\nCONFIG: {} found\n".format(configFile))
        clientAnonymizer.readConfiguration(configFile)

        res = input("\nDo you want to reset the configuration? [Y/N] ").upper()

        if res == "Y":
            os.remove(configFile)
    
    print("\n=============== {} Operator config (Ctrl-C for exit) ===============".format(configType))
    
    while True:
        try:
            entity_type = input("\nEntity: ").upper()

            # Check entity validity
            if entity_type.upper() not in anonymizer.SUPPORTED_ENTITIES:
                print("CONFIG: entity '{}' not exits\n".format(entity_type))
                continue

            operator = input("Anonymizer: ").lower()

            if operator not in anonymizer.ANONYMIZERS:
                print("CONFIG: anonymizer '{}' not exists\n".format(operator))
                continue
            if operator == "hash":
                hash_type = input("Hash type (md5, sha256, sha512): ").lower()

                anonymizer.addHash(entity_type, hash_type)
            elif operator == "replace":
                new_value = input("New value: ")

                anonymizer.addReplace(entity_type, new_value)
            elif operator == "redact":
                anonymizer.addRedact(entity_type)
            elif operator == "encrypt":
                key = input("Key (128, 192 or 256 bits length): ")

                anonymizer.addEncrypt(entity_type, key)
            elif operator == "mask":
                masking_char = input("Masking char: ")
                chars_to_mask = input("Chars to mask: ")
                from_end = input("From end (True or False): ")

                anonymizer.addMask(entity_type, masking_char, chars_to_mask, from_end)
            elif operator == "decrypt":
                key = input("Key (128, 192 or 256 bits length): ")

                anonymizer.addDecrypt(entity_type, key)
            else:
                print("Invalid operator!\n")

        except KeyboardInterrupt:
            print("Configuration completed")
            time.sleep(2)
            break

def clear():
    if name == "nt":
        _ = system("cls")
    else:
        _ = system("clear")

def exit():
    while True:
        if input("\nPress Q to exit: ").lower() == "q":
            clear()
            break

if __name__ == "__main__":

    try:
        while True:
            clear()
            print(":::::::::::::::::: PRESIDIO ANONYMIZER (data loader) ::::::::::::::::::\n")
            print("1) Anonymize")
            print("2) Deanonymize")
            print("3) Server configuration")
            print("4) Quit")

            try:
                command = int(input("\nCommand: "))
            except ValueError:
                print('\nYou did not enter a valid command\n')
                continue

            if command == 1:
                clear()
                
                try:
                    clientAnonymizer
                    presidio_anonymizer_start(clientAnonymizer) 
                except NameError:
                    print("No server info found!")
                    exit() 
            elif command == 2:
                clear()
                
                try:
                    clientAnonymizer
                    presidio_deanonymizer_start(clientAnonymizer) 
                except NameError:
                    print("No server info found!")
                    exit() 
            elif command == 3:
                print("\n=============== Server config ===============\n")
                ip_address = input("IP ADDRESS: ")
                port = input("SERVER PORT: ")
                
                clientAnonymizer = anonymizer.ClientEntity(ip_address, port)
                exit()
            elif command == 4:
                print("\nQuitting..")
                time.sleep(1)
                break
            else:
                print("\nCommand not valid!\n") 
                clear() 
    except KeyboardInterrupt:
        print("Quitting...")
        sys.exit(0)