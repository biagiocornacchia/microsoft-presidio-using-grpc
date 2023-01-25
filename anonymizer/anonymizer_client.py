import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

import json
import os

SUPPORTED_ENTITIES = [
    'IBAN_CODE',
    'US_PASSPORT',
    'DATE_TIME',
    'MEDICAL_LICENSE',
    'CRYPTO',
    'LOCATION',
    'UK_NHS',
    'US_SSN',
    'CREDIT_CARD',
    'US_BANK_NUMBER',
    'US_ITIN',
    'EMAIL_ADDRESS',
    'PERSON',
    'IP_ADDRESS',
    'DOMAIN_NAME',
    'PHONE_NUMBER',
    'SG_NRIC_FIN',
    'NRP',
    'US_DRIVER_LICENSE'
]
ANONYMIZERS = [
    'hash',
    'mask',
    'redact',
    'replace',
    'custom',
    'encrypt',
    'decrypt'
]

CONFIG_FILE = os.path.join(os.path.abspath('.'), 'config', 'operator_config_anonymizer.txt')
CONFIG_FILE_DE = os.path.join(os.path.abspath('.'), 'config', 'operator_config_deanonymizer.txt')

PATH_ANONYMIZER_RESULTS = os.path.join(os.path.abspath('..'), 'anonymizer-results', '')
PATH_ANALYZER_RESULTS = os.path.join(os.path.abspath('..'), 'analyzer-results', '')
PATH_FILES = os.path.join(os.path.abspath('..'), 'files', '')


class ClientEntity:
    def __init__(self, ip_address: str, port: int) -> None:
        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(f'{ip_address}:{port}')
        self.stub = pb2_grpc.AnonymizerEntityStub(self.channel)

        self.processed_chunks = 0
        self.chunk_size = 1024 * 1024  # 1MB

    def read_configuration(self, configuration_file: str) -> bool:
        if os.path.exists(configuration_file):
            with open(configuration_file, 'r') as config_file:
                print('=============== CURRENT CONFIGURATION ===============')
                for line in config_file:
                    line_config = json.loads(line)
                    print('Entity type: ' + line_config['entity_type'])
                    print('Parameters: ' + line_config['params'] + "\n")
            return True
        return False

    def send_request_anonymize(self, filename: str) -> int:
        if not check_required_files(filename, 'anonymize'):
            return -1

        # Sending original text to anonymize
        try:
            chunk_iterator = self.generate_file_chunks(PATH_FILES + filename)
            print('\nFROM CLIENT: sending original text...')
            response = self.stub.sendFile(chunk_iterator)
            uuid_client = response.uuidClient

            if response.chunks == self.processed_chunks:
                print(f'FROM SERVER: file received correctly. UUID assigned: {uuid_client}')

                # Sending analyzer results
                print('FROM CLIENT: sending analyzer results...')
                response = self.stub.sendRecognizerResults(read_recognizer_results(filename, uuid_client))

                if response.uuidClient == uuid_client:
                    print(f'FROM SERVER: analyzer results received correctly. UUID: {uuid_client}')
                    # Sending configuration file
                    try:
                        print('FROM CLIENT: searching for a configuration file...')
                        with open(CONFIG_FILE, 'r') as config_file:
                            print('FROM CLIENT: sending configuration file...')
                            response = self.stub.sendConfig(pb2.Config(uuidClient=uuid_client,
                                                                       operators=config_file.read(),
                                                                       type='anonymize'))

                            # ACK FROM SERVER: chunks is insignificant and uuid_client is used for ack
                            if response.chunks == -1 and response.uuidClient == uuid_client:
                                print('FROM SERVER: configuration file received correctly')
                            else:  
                                print('FROM SERVER: configuration file not received correctly')
                                return 0
                    except IOError:
                        print('FROM CLIENT: using a default configuration')
                    
                    print('\nWaiting for Microsoft Presidio Anonymizer...')
                    
                    if self.send_request_for_text(filename, uuid_client, 'anonymize') == -1:
                        return -1

                    if self.send_request_for_items(filename, uuid_client, 'anonymize') == -1:
                        return -1
                    
                    return 1
                else:
                    print('FROM SERVER: analyzer results not received correctly.')
                    return 0
            else:
                print('FROM SERVER: original text file not received correctly')
                return 0
        except grpc.RpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print('Cannot connect to the server\n')
            else:
                print(f'Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n')
            return -2

    def send_request_deanonymize(self, filename: str) -> int:
        if not check_required_files(filename, 'deanonymize'):
            return -1

        # Sending anonymized text
        try:
            chunk_iterator = self.generate_file_chunks(PATH_ANONYMIZER_RESULTS + filename)
            print('\nFROM CLIENT: sending anonymized text...')
            response = self.stub.sendFile(chunk_iterator)
            uuid_client = response.uuidClient

            if response.chunks == self.processed_chunks:
                print(f'FROM SERVER: file received correctly. UUID assigned: {uuid_client}')

                # Sending items results
                print('FROM CLIENT: sending items...')
                response = self.stub.sendAnonymizedItems(read_anonymized_items(filename, uuid_client))

                if response.uuidClient == uuid_client:
                    print(f'FROM SERVER: analyzer results received correctly. UUID: {uuid_client}')

                    # sending configuration file (IS REQUIRED!)
                    print('FROM CLIENT: sending configuration file...')

                    with open(CONFIG_FILE_DE, 'r') as config_file:
                        response = self.stub.sendConfig(pb2.Config(uuidClient=uuid_client, operators=config_file.read(),
                                                                   type='deanonymize'))

                        # ACK FROM SERVER: chunks is insignificant and uuid_client is used for ACK
                        if response.chunks == -1 and response.uuidClient == uuid_client:
                            print('FROM SERVER: configuration file received correctly')
                        else:  
                            print('FROM SERVER: configuration file not received correctly')
                            return 0  
                    
                    print('\nWaiting for Microsoft Presidio Anonymizer...')

                    if self.send_request_for_text(filename, uuid_client, 'deanonymize') == -1:
                        return -1

                    if self.send_request_for_items(filename, uuid_client, 'deanonymize') == -1:
                        return -1

                    return 1
                else:
                    print('FROM SERVER: items results not received correctly.')
                    return 0
            else:
                print('FROM SERVER: anonymized text file not received correctly')
                return 0
        except grpc.RpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print('Cannot connect to the server\n')
            else:
                print(f'Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n')
            return -2

    def send_request_for_text(self, filename: str, uuid_client: str, request_type: str) -> int:
        # sends a request to get anonymized or deanonymized text
        responses = self.stub.getText(pb2.Request(uuidClient=uuid_client, type=request_type))

        if request_type == 'anonymize':
            with open(f'{PATH_ANONYMIZER_RESULTS}{filename}-anonymized.txt', 'w') as anonymizer_results:
                for response in responses:
                    if response.chunk == -1:
                        # Received a NAK
                        print('FROM SERVER: Error during anonymization')
                        return -1
                    else:
                        anonymizer_results.write(response.chunk)
                        print(f'{filename}-anonymized.txt created')
                        return 1
        else:
            filename = filename.split('-')
            with open(f'{PATH_ANONYMIZER_RESULTS}{filename[0]}-deanonymized.txt', 'w') as deanonymizer_results:
                for response in responses:
                    if response.chunk == -1:
                        # Received a NAK
                        print('FROM SERVER: Error during deanonymization')
                        return -1
                    else:
                        deanonymizer_results.write(response.chunk)
                        print(f'{filename[0]}-deanonymized.txt created')
                        return 1

    def send_request_for_items(self, filename: str, uuid_client: str, request_type: str) -> None:
        # Sends a request to get items generated during the anonymization or deanonymization
        responses = self.stub.getItems(pb2.Request(uuidClient=uuid_client, type=request_type))

        if request_type == 'anonymize':
            with open(f'{PATH_ANONYMIZER_RESULTS}{filename}-anonymized-items.json', 'w') as anonymizer_items_results:
                anonymizer_items = {'items': list()}
                for response in responses:
                    item = {
                        'operator': response.operator,
                        'entity_type': response.entity_type,
                        'start': response.start,
                        'end': response.end,
                        'text': response.text
                    }
                    anonymizer_items['items'].append(item)
                anonymizer_items_results.write(json.dumps(anonymizer_items))
            print(f'{filename}-anonymized-items.json created')
        else:
            filename = filename.split('-')
            with open(f'{PATH_ANONYMIZER_RESULTS}{filename[0]}-deanonymized-items.json', 'w') as deanonymizer_items_results:
                deanonymizer_items = {'items': list()}
                for response in responses:
                    item = {
                        'start': response.start,
                        'end': response.end,
                        'operator': response.operator,
                        'text': response.text,
                        'entity_type': response.entity_type
                    }
                    deanonymizer_items['items'].append(item)
                deanonymizer_items_results.write(json.dumps(deanonymizer_items))
            print(f'{filename[0]}-deanonymized-items.json created')

    def generate_file_chunks(self, filename: str) -> iter:
        self.processed_chunks = 0

        with open(f'{filename}.txt', 'r') as f:
            while True:
                data = f.read(self.chunk_size)

                if not data:
                    break

                self.processed_chunks += self.chunk_size
                yield pb2.DataFile(chunk=data)

    def close_connection(self):
        print('Disconnected from the server')
        self.channel.close()


def read_recognizer_results(filename: str, uuid_client: str) -> iter:
    # Reads results file generated by the analyzer
    with open(f'{PATH_ANALYZER_RESULTS}{filename}-results.json', 'r') as f:
        recognizer_results = json.loads(f.read())

        for result in recognizer_results['results']:
            yield pb2.RecognizerResult(start=result['start'], end=result['end'],
                                       score=float(result['score']), entity_type=result['entity_type'],
                                       uuidClient=uuid_client)


def read_anonymized_items(filename: str, uuid_client: str) -> iter:
    # Reads anonymized-items file generated by the anonymizer
    with open(f'{PATH_ANONYMIZER_RESULTS}{filename}-items.json', 'r') as f:
        anonymizer_results = json.loads(f.read())

        for result in anonymizer_results['items']:
            yield pb2.AnonymizedItem(uuidClient=uuid_client, start=result['start'], end=result['end'],
                                     entity_type=result['entity_type'], operator=result['operator'])


def check_required_files(filename: str, request_type: str) -> bool:
    if request_type == 'anonymize':
        if (not os.path.exists(f'{PATH_FILES}{filename}.txt')) \
                or (not os.path.exists(f'{PATH_ANALYZER_RESULTS}{filename}-results.json')):
            print('ERROR: file text or analyzer results not found')
            return False

        # Check configuration file
        config_up = 0
        if os.path.exists(CONFIG_FILE):
            config_up = 1

        if config_up == 0:
            print('Configuration file not found! (Using a default configuration)')
        else:
            print('Configuration file found')

        return True
    elif request_type == 'deanonymize':
        if (not os.path.exists(f'{PATH_ANONYMIZER_RESULTS}{filename}.txt')) \
                or (not os.path.exists(f'{PATH_ANONYMIZER_RESULTS}{filename}-items.json')):
            print('ERROR: file text anonymized or anonymized items not found')
            return False

        # Check configuration file (for deanonymization it is REQUIRED!)
        if os.path.exists(CONFIG_FILE_DE) == 0:
            print('Configuration file not found!')
            print('You have to setup a config file before deanonymize')
            return False
        else:
            print('Configuration file found')

        return True
    else:
        print('Request type not valid')


def check_duplicates(entity_type: str, configuration_file: str) -> int:
    # Checks if a config option is already set
    options = []
    found = 0

    try:
        with open(configuration_file, 'r') as f:
            for line in f:
                if entity_type not in line:
                    options.append(line)
                else:
                    print(f'Duplicate found: {line}')
                    found = 1

        with open(configuration_file, 'w') as f:
            for optionElem in options:
                f.write(optionElem)
    except IOError:
        print('CONFIG: creating a new configuration file...')

    return found


# replaces the PII text entity with new string
def add_replace(entity_type, new_value):
    found = check_duplicates(entity_type, CONFIG_FILE)
    params = '{ ' + f'\\"type\\": \\"replace\\", \\"new_value\\": \\"{new_value}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found


# hashes the PII text entity
def add_hash(entity_type, hash_type):
    found = check_duplicates(entity_type, CONFIG_FILE)
    params = '{ ' + f'\\"type\\": \\"hash\\", \\"hash_type\\": \\"{hash_type}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found


# anonymizes text to an encrypted form
def add_encrypt(entity_type, key):
    found = check_duplicates(entity_type, CONFIG_FILE)
    params = '{ ' + f'\\"type\\": \\"encrypt\\", \\"key\\": \\"{key}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found


# mask some or all given text entity PII with given character
def add_mask(entity_type, masking_char, chars_to_mask, from_end):
    found = check_duplicates(entity_type, CONFIG_FILE)
    # from_end values: true or false only
    params = '{ ' + f'\\"type\\": \\"mask\\", \\"masking_char\\": \\"{masking_char}\\", \\"chars_to_mask\\": {int(chars_to_mask)}, \\"from_end\\": {from_end.lower()}' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found


# decrypt text to from its encrypted form
def add_decrypt(entity_type, key):
    found = check_duplicates(entity_type, CONFIG_FILE_DE)
    params = '{ ' + f'\\"type\\": \\"decrypt\\", \\"key\\": \\"{key}\\"' + ' }'

    with open(CONFIG_FILE_DE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found


# replaces the PII text entity with empty string
def add_redact(entity_type):
    found = check_duplicates(entity_type, CONFIG_FILE)
    params = '{ ' + f'\\"type\\": \\"redact\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found
