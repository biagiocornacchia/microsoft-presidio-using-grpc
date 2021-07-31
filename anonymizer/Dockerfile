FROM ubuntu:20.04

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev 
RUN pip3 install --upgrade pip

RUN pip3 install presidio-anonymizer
RUN pip3 install numpy
RUN pip3 install spacy

RUN mkdir /anonymizer 
WORKDIR /anonymizer
COPY . /anonymizer
RUN chmod 777 /anonymizer/anonymizer-temp

RUN pip3 install -r requirements.txt

RUN useradd app
USER app

ENTRYPOINT [ "python3","-u","anonymizer_server.py" ]