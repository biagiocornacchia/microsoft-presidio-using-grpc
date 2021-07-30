## Generate gRPC classes for Python

Our gRPC service is defined using protocol buffers so first you need to generate the gRPC client and server interfaces from .proto service definition.
\
In the `anonymizer` and `analyzer` folder use the following command to generate the Python code:

```bash
python -m grpc_tools.protoc --proto_path=. ./proto/model.proto --python_out=. --grpc_python_out=.
```

## Presidio Analyzer

The Analyzer Service has four service methods

```protobuf
service AnalyzerEntity {
    rpc sendFileToAnalyze(stream DataFile) returns (Ack); 
    rpc sendEngineOptions(AnalyzerEngineOptions) returns (Ack);
    rpc sendOptions(AnalyzeOptions) returns (Ack);
    rpc GetAnalyzerResults(Request) returns (stream AnalyzerResults);
}
```

- `sendFileToAnalyze` </br> is used by the data loader to send the original text file that needs to be analyzed. Files will be divided into chunks. The server will assign a UUID that will be used during all the communication to identify uniquely the client information

- `sendEngineOptions`</br> AnalyzerEngine can be configured. Available options are:
    1. registry: an optional list of recognizers, that will be available instead of the predefined recognizers
    2. deny_list
    3. regex
    4. log_decision_process: defines whether the decision process within the analyzer should be logged or not.
    5. default_score_threshold: minimum confidence value for detected entities to be returned
    6. supported_languages: list of possible languages this engine could be run on. Used for loading the right NLP models and recognizers for these languages.
    
    Using this method the client eventually specifies analyzer engine options and sends them to the server. The server will store them into a json file and will return an acknowledgement message containing the UUID assigned from the server to the client during the first step.

- `sendOptions` </br> AnalyzerEngine.analyze() can also be configured. Available options are:
    1. language: the language of the text 
    2. entities: list of PII entities that should be looked for in the text. If entities value is None then all entities are looked for.
    3. correlation_id: cross call ID for this request
    4. score_threshold: A minimum value for which to return an identified entity
    5. return_decision_process: it decides if the analysis decision process steps returned in the response.
                        
    Using this method the client specifies eventually his options and sends them to the server. The server will store them into a json file and returns and Ack message containing UUID assigned from the server to the client during the first step.

- `GetAnalyzerResults` </br> The client specifies his UUID and makes a request to get analyzer results. 
The server uses the original text and eventually json files containing the options specified by the client and performs the analysis. Then it returns found entities in the text, so the client will save them into a file called `"filename-results.txt"` which resides in `analyzer-results` folder.

### An example

File demo2.txt contains
        
    Kate's social security number is 078-05-1126.  Her driver license? it is 1234567A.

First you have to configure the server (in this example localhost:8061)

    :::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::

    1) Analyzer
    2) Server configuration
    3) Quit

    Command: 2

    IP ADDRESS: localhost
    SERVER PORT: 8061

Select `analyze` (command 3) and choose the file to analyze

    SERVER INFO: localhost:8061

    1) Setup AnalyzerEngine
    2) Setup Analyze params
    3) Analyze
    4) Back

    Command: 3

    Filename: demo2

Analyzer results saved into `analyzer-results/` folder (analyzer-results/demo2-results.txt) will be
    
    { "start": 0, "end": 4, "score": 0.85, "entity_type": "PERSON" }
    { "start": 33, "end": 44, "score": 0.85, "entity_type": "US_SSN" }
    { "start": 73, "end": 81, "score": 0.65, "entity_type": "US_DRIVER_LICENSE" }

## NOTE

It is also possible adapt Presidio to detect new types of PII entities.
1. Deny-list based PII recognition
2. Regex based PII recognition

To use this features you have to setup an AnalyzeEngine configuration.

### First Case (deny list)
    
In this example, we will pass a short list of tokens which should be marked as PII if detected. First, let's define the tokens we want to treat as PII. In this case it would be a list of titles:

    1) Setup AnalyzerEngine    
    2) Setup Analyze params    
    3) Analyze
    4) Back

    Command: 1

Select PII recognition and then deny-list based PII recognition (command 1)

    1) PII recognition
    2) Other options
    3) Back

    Command: 1

    1) Deny-list based PII recognition
    2) Regex based PII recognition
    3) Back

    Command: 1

Choose an entity name and the tokens we want to treat as PII

    Entity: TITLE

    NOTE: separate values with commas.

    Values list: Mr.,Miss.,Mrs.

Text example:
    
    "I suspect Mr. Plum, in the Dining Room, with the candlestick"

    Result:
    [type: TITLE, start: 10, end: 13, score: 1.0]
    [type: PERSON, start: 14, end: 18, score: 1.0]

### Second Case (regex)

File zip_test.txt contains

    My zip code is 90210

Another simple recognizer we can add is based on regular expressions. In this case we would implement a zip code recognizer. 
    
    1) Setup AnalyzerEngine    
    2) Setup Analyze params    
    3) Analyze
    4) Back

    Command: 1

Select PII recognition and then Regex based PII recognition (command 2)

    1) Deny-list based PII recognition
    2) Regex based PII recognition
    3) Back

    Command: 2

Define the entity name, name pattern, regex pattern, score and eventually context words to increase the confidence (this parameter is optional)

    Entity: US_ZIP_CODE
    Name Pattern: us zip code
    Regex: (\b\d{5}(?:\-\d{4})?\b)
    Score: 0.01

    NOTE: separate context words with commas.

    Context words: 

Analyzer results will be

    Result:
    [type: US_ZIP_CODE, start: 15, end: 20, score: 0.1]