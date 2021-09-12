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
    rpc getAnalyzerResults(Request) returns (stream AnalyzerResults);
}
```

- `sendFileToAnalyze` </br> is used by the data loader to send the original text file that needs to be analyzed. Files will be divided into chunks. The server will assign a UUID that will be used during all the communication to identify uniquely the client information

- `sendEngineOptions`</br> The analyzer engine can be configured. Available options are:
    1. registry - an optional list of recognizers, that will be available instead of the predefined recognizers
    2. log_decision_process - defines whether the decision process within the analyzer should be logged or not.
    3. default_score_threshold - minimum confidence value for detected entities to be returned
    4. supported_languages - list of possible languages this engine could be run on. Used for loading the right NLP models and recognizers for these languages.
    
    Using this method the client eventually specifies analyzer engine options and sends them to the server. The server will store them into a json file and will return an acknowledgement message containing the UUID assigned from the server to the client during the first step.

- `sendOptions` </br> The analyze function can also be configured. Available options are:
    1. language - the language of the text 
    2. entities - list of PII entities that should be looked for in the text. If entities value is None then all entities are looked for.
    3. correlation_id - cross call ID for this request
    4. score_threshold - A minimum value for which to return an identified entity
    5. return_decision_process - it decides if the analysis decision process steps returned in the response.
                        
    Using this method the client specifies eventually his options and sends them to the server. The server will store them into a json file and returns and Ack message containing the UUID assigned from the server to the client during the first step.

- `getAnalyzerResults` </br> The client specifies his UUID and makes a request to get analyzer results. 
The server uses the original text and eventually json files containing the options specified by the client and performs the analysis. Then it returns found entities in the text, so the client will save them into a file called `"filename-results.txt"` which resides in `analyzer-results` folder.

## Installation

To run examples:

    $ git clone https://github.com/biagiocornacchia/microsoft-presidio.git
    
    $ pip3 install --upgrade pip
    $ pip3 install presidio-analyzer
    $ pip3 install spacy numpy

    $ python3 -m spacy download en_core_web_lg
    $ python3 -m pip install grpcio grpcio-tools

From the `microsoft-presidio/analyzer` directory:

1) Run the server
    ```console
    $ python analyzer_server.py
    ```
2) From another terminal, run the client (dataloader)
    ```console
    $ python data_loader.py
    ```
    or (to run the graphical user interface)
    ```console
    $ python clientGUI.py
    ```
Now you have just run a client-server application with gRPC!</br>

## An example

File demo2.txt (which resides in the `files` folder) contains
        
    Kate's social security number is 078-05-1126.  Her driver license? it is 1234567A.

First you have to configure the server (in this example localhost:8061)

    :::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::

    1) Analyzer
    2) Server configuration
    3) Quit

    Command: 2

    =============== Server config ===============

    IP ADDRESS: localhost
    SERVER PORT: 8061

Select `analyze` (command 3) and choose the file to analyze

    SERVER INFO: localhost:8061

    1) Setup AnalyzerEngine
    2) Setup Analyze params
    3) Analyze
    4) Back

    Command: 3

    How many files do you want to analyze? 1
    1) Filename: demo2

Analyzer results saved into `analyzer-results/` folder (analyzer-results/demo2-results.txt) will be
    
    { "start": 0, "end": 4, "score": 0.85, "entity_type": "PERSON" }
    { "start": 33, "end": 44, "score": 0.85, "entity_type": "US_SSN" }
    { "start": 73, "end": 81, "score": 0.65, "entity_type": "US_DRIVER_LICENSE" }

## NOTE

It is also possible adapt Presidio to detect new types of PII entities.
1. Deny-list based PII recognition
2. Regex based PII recognition

To use this features you have to setup an AnalyzeEngine configuration.

### First Case (Deny List based PII recognition)
    
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

### Second Case (Regex based PII recognition)

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

Define the entity name, number of patterns, name pattern, regex pattern, score and eventually context words to increase the confidence (this parameter is optional)

    Entity: US_ZIP_CODE

    Number of patterns: 1

    Name Pattern: us zip code
    Regex: (\b\d{5}(?:\-\d{4})?\b)
    Score: 0.01 

    NOTE: separate context words with commas.

    Context words: zip,zipcode

Analyzer results will be

    Result:
    [type: US_ZIP_CODE, start: 15, end: 20, score: 0.4]

## Scheme API

`analyzer_client.py` contains a ClientEntity class and some utility functions.

### Global vars

```python
ENGINE_OPTIONS = [ "deny_list", "regex", "nlp_engine", "app_tracer", "log_decision_process", "default_score_threshold", "supported_languages" ]
ANALYZE_OPTIONS = ["language", "entities", "correlation_id", "score_threshold", "return_decision_process"]

PATH_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"
```

This variables are used to setup a configuration for the analyzer. </br>
* `ENGINE_OPTIONS` and `ANALYZER_OPTIONS` are the possible options that Microsoft Presidio Analyzer supports.</br>
* `PATH_RESULTS` and `PATH_FILES` are the directories where the analyzer results will be saved and where the orignal text resides.

### Connection 
You should first establish a connection between the gRPC analyzer client and the gRPC analyzer server. Here are two functions to manage connections:

```python
class ClientEntity:

    def __init__(self, ip_address, port):

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(ip_address + ':' + str(port))
        self.stub = pb2_grpc.AnalyzerEntityStub(self.channel)

        self.engine_curr_config = {}
        self.analyze_curr_config = {}
        
        .
        .

    def closeConnection(self):
        print("Disconnected from the server")
        self.channel.close()
```

The arguments are a string that denote the server ip address and a number to denote the server port. </br>
`self.engine_curr_config` and `self.analyze_curr_config` will contain the current configuration specified by the client.

### Setup a configuration

```python
class ClientEntity:
        .
        .

    def setupDenyList(self, supported_entities, valuesList):
        jsonString = "{ " + f'"supported_entity": {supported_entities}, "deny_list": {valuesList}' + " }"
        self.engine_curr_config["deny_list"] = jsonString.replace("'", "\"")
    
    def setupRegex(self, supported_entity, patterns, context):
        self.engine_curr_config['regex'] = "{ " + f'"supported_entity": "{supported_entity}", "pattern": {patterns}, "context": "{context}" ' + " }"

    def setupOptions(self, option, value, optionFile):

        if optionFile == "ANALYZE_OPTIONS":
            if option in ANALYZE_OPTIONS:
                self.analyze_curr_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        elif optionFile == "ENGINE_OPTIONS":
            if option in ENGINE_OPTIONS:
                self.engine_curr_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        else:
            # invalid optionFile 
            return -2
```

`setupDenyList` has two arguments:
1. a list of the supported entity 
2. a list of words to detect

`setupRegex` has three arguments:
1. the entity supported by this recognizer
2. one or more patterns that define the recognizer
3. list of context words to help detection

`setupOptions` is used to setup all the others options specifying the right options file (ANALYZER_OPTIONS or ENGINE_OPTIONS) and returns an integer.

In the end, to perform analysis there is a function: `sendRequestAnalyze(filename)` </br>This function takes an argument (a filename) and (after a check for the required files) sends the original text file (divided into chunks of 1 MB) and eventually the AnalyzerEngine and the analyze function configuration. Then makes a request to get the analyzer results (calling `self.stub.getAnalyzerResults(pb2.Request(uuidClient = my_uuid))`). </br> It returns an integer:
* if some required files do not exist or the request for the analyzer results fails returns -1
* if there is a gRPC exception such as 'server unavailable' returns -2
* if some required files were not received correctly by the server return 0
* if the operation was successful returns 1

### Example

```python
import analyzer_client as analyzer

if __name__ == "__main__":

    clientAnalyzer = analyzer.ClientEntity("localhost", 8061)

    # Setup entities that this recognizer can detect 
    option_name = "entities"
    values = "US_ZIP_CODE"
    clientAnalyzer.setupOptions(option_name, values, "ANALYZE_OPTIONS")

    # Setup a regex configuration
    supported_entity = "US_ZIP_CODE"
    context = "zip,zipcode"

    patterns = analyzer.createPatternInfo(1, ["zip code us"], [r"(\b\d{5}(?:\-\d{4})?\b)"], [0.01])
    clientAnalyzer.setupRegex(supported_entity, patterns, context)

    clientAnalyzer.sendRequestAnalyze("zip_test")
    clientAnalyzer.closeConnection()
```
`createPatternInfo(num, nameList, regexList, scoreList)` is an utility fuction that has 4 arguments and returns a list of pattern:
1. num - number of patterns
2. nameList - list of name pattern
3. regexList - list of regex
4. scoreList - list of scores

This is an example of a deny-list based setup.

```python
	# Setup a deny list config
	supported_entities = []
	valuesList = []

	supported_entities.append("TITLE")
	valuesList.append("Mr.,Mrs.,Miss")

	supported_entities.append("PRONOUN")
	valuesList.append("he,He,his,His,she,She,hers,Hers")

	clientAnalyzer.setupDenyList(supported_entities, valuesList)
	
	clientAnalyzer.sendRequestAnalyze("double_recognizer")
	clientAnalyzer.closeConnection()
```
## Deployment
From the microsoft-presidio/analyzer directory

1) Build the docker image
```console
docker build -t grpc-analyzer .
```
2) Run the docker image
```console
docker run –dp 8061:8061 grpc-analyzer
```
3) The docker run internally executes analyzer_server.py. Open one more terminal and run the client which now can access the docker server
```console
python data_loader.py
```