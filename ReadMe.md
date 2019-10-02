# gcp_timeliner.py  
gcp_timeliner.py is a python 3.5.3+ tool designed to enable flexible transformation of Google Cloud Platform json logs to normalised csv, xlsx or timesketch format. Json logs are mapped to a normalised field set based on conditions specified in 'map' files. If a log doesn't match the conditions in a 'map' file, gcp_timeliner.py will use a default map.

The xlsx output of gcp_timeliner.py can be imported into the included colourised_template.xslx for assisted data analysis and stacking.

![alt text](https://i.ibb.co/4YckcwH/bbb.png "Timeline example")

## Input format support
gcp_timeliner.py is designed to work with a file of single line json logs, as produced by GCP during export to a Google Cloud Storage sink. E.g.
```
{"insertId":"6y6dfde2p4wu","logName":"projects [...] }
{"insertId":"6y6dfde2p4ww","logName":"projects [...] }
{"insertId":"-ajhlaze80biz","logName":"projects [...] }
```

To collect or manipulate logs in this format, you can use gcp_log_toolbox.py

## Output format support
gcp_timeliner.py supports the following output formats:
* csv (the actual output is pipe separated, as commas are frequently in the json output)
* xlsx
* timesketch

Specify the format using the --format argument. Based on the selected output format, gcp_timeliner.py will modify the output in the following ways:

### csv
Each log entry will be written to a single line in a pipe separated format.

### xlsx
The same as csv, however special formatting characters will be added to simulate nested json formatting in xlsx cells. As a result, each log may span multiple lines, which formats well in excel however breaks single line grep-abiblity.

### timesketch
Writes each log to a single line json entry, with field transformations to meet the TimeSketch expected format. Transformations applied to the log include:
* timestamp -> renamed to 'datetime'  
* method -> renamed to 'timestamp_desc'  
* summary -> renamed to 'message', and prepended with the strings from 'method' and 'severity' in square brackets.

## Timeline creation
A timeline can be created from a single json file.  

Syntax:  
```
python gcp_timeliner.py -f log.json -o timeline.tsv --format xlsx
```

## Importing into TimeSketch
After generating a timeine using the `--format timesketch` argument, follow these steps to import the file into TimeSketch.

* Ensure the output file has a .jsonl extension
* Copy the .jsonl file to the TimeSketch server
* Run the following command to import the .jsonl file into the TimeSketch timeline:
```
tsctl import --file input.jsonl --username admin --timeline_name gcp_timeliner
```

## Colourised Template
For easy review and filtering, load the timeline tsv file into the A1 cell in the Microsoft Excel template included in this project.

## Map Files
If you would like to adjust the way gcp_timeliner.py parses certain json logs, you can create a new map file. Map files consist of conditions and field allocations in json format.

Example map file:
```
{
	"conditions":{
		"resource.type":"logging_sink",  
        	"severity":"*"
	},
	"fields":{
		"insertId":"insertId",
		"timestamp":"timestamp",
		"map":"string[loggingSink_create]",
		"project":"resource.labels.project_id",
		"account":"protoPayload.authenticationInfo.principalEmail",
		"ip":"protoPayload.requestMetadata.callerIp",
		"userAgent":"protoPayload.requestMetadata.callerSuppliedUserAgent",
		"type":"resource.type",
		"method":"protoPayload.methodName",
		"severity":"severity",
		"summary":"resource.labels.name,protoPayload.request.sink.destination",
		"detail":"[fulljson]"
	}
}
```

### Conditions
Conditions are compared against a json log entry to see if the map should be applied. Only one special character is supported for condition fields:

* \*  The asterisk returns True if the json field exists in the log.

All conditions must match for a map to be applied.

### Fields
Fields define which json values should be included in each csv field. Multiple values can be inserted into one csv field by separating two json fields with a comma.

E.g.
```
"detail":"resource.labels.name,ProtoPayload.request.sink.destination"
```

The following techniques can input non-standard values in a csv column:
* string[text to put in field]  - A string will be inserted instead of a json field
* [fulljson] - the full json log will be inserted into the field
