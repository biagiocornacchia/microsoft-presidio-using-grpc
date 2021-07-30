## Generate gRPC classes for Python

Our gRPC service is defined using protocol buffers so first you need to generate the gRPC client and server interfaces from .proto service definition.
\
In the `anonymizer` and `analyzer` folder use the following command to generate the Python code:

```bash
python -m grpc_tools.protoc --proto_path=. ./proto/model.proto --python_out=. --grpc_python_out=.
```

## Presidio Anonymizer

The Analyzer Service has six service methods

```protobuf
service AnonymizerEntity {
    rpc sendRecognizerResults(stream RecognizerResult) returns (FileAck);
    rpc sendAnonymizedItems(stream AnonymizedItem) returns (FileAck);
    rpc sendConfig(Config) returns (FileAck);
    rpc sendFile(stream DataFile) returns (FileAck);
    rpc getText(Request) returns (stream DataFile);
    rpc getItems(Request) returns (stream Item);
}
```

- `sendRecognizerResults` </br> is used by the data loader to send the found entities in the text. RecognizerResult is an exact copy of the RecognizerResult object from presidio-analyzer. Indeed the message contains the start location of the detected entity, the end location of the detected entity, the score of the detection and the type of the entity.

    ```protobuf
    message RecognizerResult {
        int32 start = 1;
        int32 end = 2;
        float score = 3;
        string entity_type = 4;
        string uuidClient = 5; 
    }
    ```

- `sendAnonymizedItems` </br> is used by the data loader to send a list of information about the anonymized entities to perform deanoymization. In this case the message contains the start index of the changed text, the end index of the changed text and the type of the entity.

    ```protobuf
    message AnonymizedItem {
        int32 start = 1;
        int32 end = 2;
        string entity_type = 3;
        string uuidClient = 4; 
    }
    ```

- `sendConfig`</br> is used to create an operator configuration. Possible operators for the anonymizer are:
    1. encrypt: anonymize the text with an encrypted text using Advanced Encryption Standard
    2. replace: replaces the PII text entity with a new string
    3. redact: redact the string - empty value
    4. mask: mask a given amount of text with a given character
    5. hash: hash given text with sha256/sha512/md5 algorithm

    Configuration file is called `operatorConfigAnonymizer` and resides in the `config` folder.</br>
    
    Insted for deanonymization is supported only one operator:
    1. decrypt: decrypt text to from its encrypted form using the key supplied by the user for the encryption

    Configuration file is called `operatorConfigDenonymizer` and resides in the `config` folder. 

- `sendFile` </br> is used by the data loader to send the original text file that needs to be anonymized. Files will be divided into chunks. The server will assign a UUID that will be used during all the communication to identify uniquely the client information.

- `getText` </br> The client specifies his UUID and specifies the type of request (anonymization or deanonymization). For anonymization the result will be saved into a file called `"filename-anonymized.txt"` which resides in the `anonymized-results` folder. Instead, for deanonymization the result will be saved into a file called `"filename-deanoymized.txt"` that resides in the same folder.

- `getItems` </br> The client specifies his UUID and makes a request to get items. Anonymize() and Deanonymize() function returns the anonymized text and a list of items that contains information about the anonymized/deanonymized entities. For anonymization the result will be saved into a file called `"filename-anonymized-items.txt"` which is contained in the `anonymized-results` folder. Instead, for deanonymization the result will be saved into a file called `"filename-deanonymized-items.txt"` which is contained in the same folder.

### An example of anonymization

File demo2.txt contains
        
    Kate's social security number is 078-05-1126.  Her driver license? it is 1234567A.

File demo2-results.txt contains

    { "start": 0, "end": 4, "score": 0.85, "entity_type": "PERSON" }
    { "start": 33, "end": 44, "score": 0.85, "entity_type": "US_SSN" }
    { "start": 73, "end": 81, "score": 0.65, "entity_type": "US_DRIVER_LICENSE" }

First you have to configure the server (in this example localhost:8061)

    :::::::::::::::::: PRESIDIO ANONYMIZER (data loader) ::::::::::::::::::

    1) Anonymize
    2) Deanonymize
    3) Server configuration
    4) Quit

    Command: 3

    IP ADDRESS: localhost
    SERVER PORT: 8061

Select `anonymize` (command 1) and setup a configuration file for the anonymizer.
</br></br>NOTE: setup a configuration is optional. When performing anonymization, if anonymizers map is empty the default anonymization operator is "replace" for all entities. The replacing value will be the entity type e.g.: <PHONE_NUMBER>

    SERVER INFO: localhost:8061

    1) Setup config file
    2) Read the current config
    3) Start anonymization
    4) Back

    Command: 1

    Anonymizer Operator config (press Q for exit)

    Entity: PERSON 
    Anonymizer: encrypt
    ** encrypt **
    Key: AAECAwQFBgcICQoLDA0ODw==

So we can start anonymization using command 3 and choosing a file (in this case demo2)

    1) Setup config file
    2) Read the current config
    3) Start anonymization
    4) Back

    Command: 3

    Filename: demo2

Anonymizer results saved into `anonymizer-results/` folder (anonymizer-results/demo2-anonymized.txt and anonymizer-results/demo2-anonymized-items.txt) will be

    J4I4V8mL4sy2r5DNRqSiN5lQJzU2XLJFhwMNHAh1jmQ='s social security number is <US_SSN>.  Her driver license? it is <US_DRIVER_LICENSE>.
    
    Anonymized items:
    { "operator": "replace", "entity_type": "US_DRIVER_LICENSE", "start": 110, "end": 129, "text": "<US_DRIVER_LICENSE>" }
    { "operator": "replace", "entity_type": "US_SSN", "start": 73, "end": 81, "text": "<US_SSN>" }
    { "operator": "encrypt", "entity_type": "PERSON", "start": 0, "end": 44, "text": "J4I4V8mL4sy2r5DNRqSiN5lQJzU2XLJFhwMNHAh1jmQ=" }

### An example of deanonymization

This example take the output of the AnonymizerEngine with `encrypted` PII entity, and decrypts it back to the original text

Firstly, we must setup a config file specifyng the cryptographic key used for the encryption
        
    1) Setup config file
    2) Read the current config
    3) Start deanonymization
    4) Back

    Command: 1

    Deanonymizer Operator config (press Q for exit)

    Entity: PERSON
    Anonymizer: decrypt
    ** decrypt **
    Key: AAECAwQFBgcICQoLDA0ODw==

Deanonymizer results saved into `anonymizer-results/` folder (anonymizer-results/demo2-deanonymized.txt and anonymizer-results/demo2-deanonymized-items.txt) will be

    Kate's social security number is <US_SSN>.  Her driver license? it is <US_DRIVER_LICENSE>.
    
    Items:
    { "start": 0, "end": 4, "operator": "decrypt", "text": "Kate", "entity_type": "NUMBER" }

