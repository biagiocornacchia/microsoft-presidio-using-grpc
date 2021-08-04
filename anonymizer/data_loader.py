import anonymizer_client as anonymizer
import os
from os import system, name
import time

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
            exit()

        elif command == 2:
            
            if not clientAnonymizer.readConfiguration(anonymizer.CONFIG_FILE):
                print("Configuration file not found!")

            exit()

        elif command == 3:

            filename = input("\nFilename: ")

            if clientAnonymizer.sendRequestAnonymize(filename) != -1:
                print("\nSuccess!")
            else:
                print("\nFile missing!")

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
            exit()

        elif command == 2:

            if not clientAnonymizer.readConfiguration(anonymizer.CONFIG_FILE_DE):
                print("Configuration file not found!")

            exit()

        elif command == 3:

            filename = input("\nFilename (ex. filename-anonymized): ")

            if clientAnonymizer.sendRequestDeanonymize(filename) != -1:
                print("\nSuccess!")
            else:
                print("\nFile missing!")

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
        print("ConfigFile not valid!")

    if os.path.exists(configFile):
        print("\nCONFIG: {} found".format(configFile))

        res = input("\nDo you want to reset the configuration? [Y/N] ").upper()

        if res == "Y":
            os.remove(configFile)
    
    print("\n{} Operator config (press Q for exit)\n".format(configType))
    
    while True:
        entity_type = input("Entity: ").upper()

        # QUITTING
        if entity_type == "Q" or entity_type == "QUIT":
            print("Quitting config..")
            break

        # NOT EXISTS
        if entity_type.upper() not in anonymizer.SUPPORTED_ENTITIES:
            print("CONFIG: entity '{}' not exits\n".format(entity_type))
            continue
                
        # CHECK FOR DUPLICATES
        check = anonymizer.checkDuplicate(entity_type, configFile) 

        if check == 1:
            print("CONFIG: resetting config file")
            os.remove(configFile)
        elif check == 0:
            print("CONFIG: ignoring...")
            continue

        operator = input("Anonymizer: ").lower()

        if operator not in anonymizer.ANONYMIZERS:
            print("CONFIG: anonymizer '{}' not exists\n".format(operator))
            continue


        ######## if operator == hash, if operator == encrypt etc

        if operator == "hash":
            hash_type = input("Hash type (md5, sha256, sha512): ").lower()

            anonymizer.addHash(entity_type, hash_type)

        elif operator == "replace":
            new_value = input("New value: ")

            anonymizer.addReplace(entity_type, new_value)

        elif operator == "redact":
            anonymizer.addRedact(entity_type)

        elif operator == "encrypt":
            key = input("Key: ")

            anonymizer.addEncrypt(entity_type, key)

        elif operator == "mask":
            masking_char = input("Masking char: ")
            chars_to_mask = input("Chars to mask: ")
            from_end = input("From end (True or False): ")

            anonymizer.addMask(entity_type, masking_char, chars_to_mask, from_end)
        
        elif operator == "decrypt":
            key = input("Key: ")

            anonymizer.addDecrypt(entity_type, key)

        else:
            print("Invalid operator!\n")

        #print("\n{} -> {} - Config successfully updated.\n".format(entity_type, params))

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

            ip_address = input("\nIP ADDRESS: ")
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