import anonymizer_client as anonymizer
import os
from os import system, name
import time
import sys


def presidio_anonymizer_start(client_anonymizer):
    print(f'SERVER INFO: {client_anonymizer.ip_address}:{client_anonymizer.port}')

    while True:
        print('\n1) Setup config file')
        print('2) Read the current config')
        print('3) Start anonymization')
        print('4) Back')

        command = int(input('\nCommand: '))
        if command == 1:
            setup_config(client_anonymizer, anonymizer.CONFIG_FILE)
            clear()
        elif command == 2:
            if not client_anonymizer.read_configuration(anonymizer.CONFIG_FILE):
                print("Configuration file not found!")
            close()
        elif command == 3:
            filename_list = []

            num_files = int(input("\nHow many files do you want to anonymize? "))
            for i in range(num_files):
                filename_list.append(input(f"{i + 1}) Filename: "))

            for filename in filename_list:
                print(f'\n=============== {filename} ANONYMIZATION ===============\n')

                if client_anonymizer.send_request_anonymize(filename) != -1:
                    print(f'\n{filename} anonymized successfully!\n')
                else:
                    print(f'\nFile missing for {filename}!\n')
            close()
        elif command == 4:
            break
        else:
            print("\nCommand not valid!")


def presidio_deanonymizer_start(client_anonymizer):
    print(f'SERVER INFO: {client_anonymizer.ip_address}:{client_anonymizer.port}')

    while True:
        print('\n1) Setup config file')
        print('2) Read the current config')
        print('3) Start deanonymization')
        print('4) Back')

        command = int(input("\nCommand: "))
        if command == 1:
            setup_config(client_anonymizer, anonymizer.CONFIG_FILE_DE)
            clear()
        elif command == 2:
            if not client_anonymizer.read_configuration(anonymizer.CONFIG_FILE_DE):
                print("Configuration file not found")
            close()
        elif command == 3:
            filename_list = []

            num_files = int(input("\nHow many files do you want to anonymize? "))
            for i in range(num_files):
                filename_list.append(input(f'{i + 1}) Filename (ex. filename-anonymized): '))

            for filename in filename_list:
                print(f'\n=============== {filename} DEANONYMIZATION ===============\n')

                if client_anonymizer.send_request_deanonymize(filename) != -1:
                    print(f'\n{filename} deanonymized successfully!\n')
                else:
                    print(f'\nFile missing for {filename}!\n')
            close()
        elif command == 4:
            break
        else:
            print('\nCommand not valid!')


def setup_config(client_anonymizer, config_file):
    if config_file == anonymizer.CONFIG_FILE:
        config_type = 'Anonymizer'
    elif config_file == anonymizer.CONFIG_FILE_DE:
        config_type = 'Deanonymizer'
    else:
        print('ERROR: configuration file not valid!')

    if os.path.exists(config_file):
        print(f'\nCONFIG: {config_file} found\n')
        client_anonymizer.read_configuration(config_file)

        res = input('\nDo you want to reset the configuration? [Y/N] ').upper()
        if res == 'Y':
            os.remove(config_file)

    print(f'\n=============== {config_type} Operator config (Ctrl-C for close) ==============')
    while True:
        try:
            entity_type = input('\nEntity: ').upper()

            # Check entity validity
            if entity_type.upper() not in anonymizer.SUPPORTED_ENTITIES:
                print(f'CONFIG: entity \'{entity_type}\' not exits\n')
                continue

            operator = input('Anonymizer: ').lower()
            if operator not in anonymizer.ANONYMIZERS:
                print(f'CONFIG: anonymizer \'{operator}\' not exists\n')
                continue
            if operator == 'hash':
                hash_type = input('Hash type (md5, sha256, sha512): ').lower()
                anonymizer.add_hash(entity_type, hash_type)
            elif operator == 'replace':
                new_value = input('New value: ')
                anonymizer.add_replace(entity_type, new_value)
            elif operator == 'redact':
                anonymizer.add_redact(entity_type)
            elif operator == 'encrypt':
                key = input('Key (128, 192 or 256 bits length): ')
                anonymizer.add_encrypt(entity_type, key)
            elif operator == 'mask':
                masking_char = input('Masking char: ')
                chars_to_mask = input('Chars to mask: ')
                from_end = input('From end (True or False): ')
                anonymizer.add_mask(entity_type, masking_char, chars_to_mask, from_end)
            elif operator == 'decrypt':
                key = input('Key (128, 192 or 256 bits length): ')
                anonymizer.add_decrypt(entity_type, key)
            else:
                print('Invalid operator!\n')
        except KeyboardInterrupt:
            print('Configuration completed')
            time.sleep(2)
            break


def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def close():
    while True:
        if input('\nPress Q to close: ').lower() == 'q':
            clear()
            break


if __name__ == '__main__':
    try:
        while True:
            clear()
            print(':::::::::::::::::: PRESIDIO ANONYMIZER (data loader) ::::::::::::::::::\n')
            print('1) Anonymize')
            print('2) Deanonymize')
            print('3) Server configuration')
            print('4) Quit')

            try:
                command = int(input('\nCommand: '))
            except ValueError:
                print('\nYou did not enter a valid command\n')
                continue

            if command == 1:
                clear()
                try:
                    clientAnonymizer
                    presidio_anonymizer_start(clientAnonymizer)
                except NameError:
                    print('No server info found!')
                    close()
            elif command == 2:
                clear()
                try:
                    clientAnonymizer
                    presidio_deanonymizer_start(clientAnonymizer)
                except NameError:
                    print('No server info found!')
                    close()
            elif command == 3:
                print('\n=============== Server config ===============\n')
                ip_address = input('IP ADDRESS: ')
                port = input('SERVER PORT: ')

                clientAnonymizer = anonymizer.ClientEntity(ip_address, port)
                close()
            elif command == 4:
                print('\nQuitting..')
                time.sleep(1)
                break
            else:
                print('\nCommand not valid!\n')
                clear()
    except KeyboardInterrupt:
        print('Quitting...')
        sys.exit(0)
