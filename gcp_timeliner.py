import os
import csv
import json
import logging
import argparse
from time import gmtime, strftime


# Function to read json map into python object
def readMap(mapPath):
    """Reads a map file into a json object

    Args:
        mapPath: file system path to map file

    Returns:
        parsed map as a json object
    """
    with open(mapPath, 'r') as f:
        map = json.load(f)
    return map


def writeCsv(out, writer):
    """Writes output to TSV

    Args:
        out: The object to be written to TSV
        writer: the csv/tsv writer object

    Returns:
        nothing
    """
    writer.writerow({
                    'insertId': out['insertId'],
                    'timestamp': out['datetime'],
                    'map': out['map'],
                    'project': out['project'],
                    'account': out['account'],
                    'ip': out['ip'],
                    'userAgent': out['userAgent'],
                    'type': out['type'],
                    'method': out['timestamp_desc'],
                    'severity': out['severity'],
                    'summary': out['message'],
                    'detail': out['detail']})


def writeTimeSketch(out, outputFile):
    """Writes output to json lines (jsonl) format for TimeSketch

    Args:
        out: The object to be written to a json line
        outputFile: The file to be writen

    Returns:
        nothing
    """
    out['message'] = "[" + out['timestamp_desc'] + "]" + "[" + out['severity'] + "] " + out['message']
    with open(outputFile, 'a+') as o:
        json.dump(out, o)
        o.write("\n")
        o.close


# Function to sanitize bad TSV noncompatable chars from output
def sanitize(x, format):
    """Santizes characters from a string to improve output formatting

    Args:
        x: string to be sanitized
        format: xlsx, csv or timesketch

    Returns:
        sanitized string
    """
    if format == "xlsx":
        if "', '" in x:
            x = x.replace(", '", ",\n'")
        if ' ; ' in x:
            x = x.replace(' ; ', ' ; \n')
        if ': {' in x:
            x = x.replace(': {', ':\n{')
        if '}, {' in x:
            x = x.replace('}, {', '},\n{')
        if '\n' in x:
            x = '"' + x
            x = x + '"'
        if '{' in x:
            o = ""
            space = ""
            y = x.split("{")
            for z in y:
                o += space + z
                space = space + "  "
            x = o
    if format == "csv":
        x = x.replace('\n', ' ')
        x = x.replace('\t', ' ')
    return x


def defaultParser(log, format):
    """Normalizes logs which do not match a map file.

    Args:
        log: Log object to be normalised
        format: xlsx, csv or timesketch

    Returns:
        normalised log object
    """
    logger.debug("applying default map to insertId:{}".format(log['insertId']))
    out = {}
    try:
        out['insertId'] = log['insertId']
    except KeyError:
        out['insertId'] = "no value"
    try:
        out['datetime'] = log['timestamp']
    except KeyError:
        out['datetime'] = "no value"
    out['map'] = "default"
    try:
        out['project'] = log['resource']['labels']['project_id']
    except KeyError:
        out['project'] = "no value"
    try:
        out['type'] = log['resource']['type']
    except KeyError:
        out['type'] = "no value"
    try:
        out['severity'] = log['severity']
    except KeyError:
        out['severity'] = "no value"
    if 'protoPayload' in log:
        if 'authenticationInfo' in log['protoPayload']:
            if 'principalEmail' in log['protoPayload']['authenticationInfo']:
                out['account'] = log['protoPayload']['authenticationInfo']['principalEmail']
            else:
                out['account'] = "no value"
        else:
            out['account'] = "no value"
        if 'requestMetadata' in log['protoPayload']:
            if 'callerIp' in log['protoPayload']['requestMetadata']:
                out['ip'] = log['protoPayload']['requestMetadata']['callerIp']
            else:
                out['ip'] = "no value"
        else:
            out['ip'] = "no value"
        if 'requestMetadata' in log['protoPayload']:
            if 'callerSuppliedUserAgent' in log['protoPayload']['requestMetadata']:
                out['userAgent'] = log['protoPayload']['requestMetadata']['callerSuppliedUserAgent']
            else:
                out['userAgent'] = "no value"
        else:
            out['userAgent'] = "no value"
        if 'methodName' in log['protoPayload']:
            out['timestamp_desc'] = log['protoPayload']['methodName']
        else:
            out['timestamp_desc'] = "no value"
        if 'serviceData' in log['protoPayload']:
            x = str(log['protoPayload']['serviceData'])
            out['message'] = x[(x.index(',')+1):]
        else:
            out['message'] = "no serviceData"
        out['detail'] = log['protoPayload']
    elif 'jsonPayload' in log:
        if 'actor' in log['jsonPayload']:
            if 'user' in log['jsonPayload']['actor']:
                out['account'] = log['jsonPayload']['actor']['user']
            else:
                out['account'] = "no account"
        else:
            out['account'] = "no account"
        out['ip'] = "na"
        if 'user_agent' in log['jsonPayload']:
            out['userAgent'] = log['jsonPayload']['user_agent']
        else:
            out['userAgent'] = "no user agent"
        if 'event_subtype' in log['jsonPayload']:
            out['timestamp_desc'] = log['jsonPayload']['event_subtype']
        else:
            out['timestamp_desc'] = "no method"
        out['message'] = "no serviceData"
        out['detail'] = log['jsonPayload']
    else:
        out['account'] = "no value"
        out['ip'] = "no value"
        out['userAgent'] = "no value"
        out['timestamp_desc'] = "no value"
        out['message'] = "no value"
        out['detail'] = log
    for value in out:
        out[value] = sanitize(str(out[value]), format)
    return out


# Function to handle non-json object special conditions
# Such as protopayload.request:"*", which checks if that json field exists
def specialConditions(condition, match):
    """Implements special condition logic to decide whether a map file matches a log or not.

    Args:
        condition: special condition type
        match: match status

    Returns:
        match status (True/False)
    """
    if condition == "*":
        pass
    else:
        match = False
    return match


# Function to check if a log line matches any map conditions
# Only supports fields 6 levels deep into a json nest
# Assumes it will match, then tries to disprove the conditions.
def processLogEntry(maps, log, format, outputFile):
    """Processes a log line.

    Args:
        maps: array of parsed map objects
        log: one line of the log file
        format: xlsx, csv or timesketch
    """
    logger.debug("Processing log:{}".format(log['insertId']))
    tracker = 0
    for m in maps:
        match = True
        for condition in m['conditions']:
            try:
                fields = condition.split(".")
                if len(fields) == 1:
                    if log[fields[0]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                elif len(fields) == 2:
                    if log[fields[0]][fields[1]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                elif len(fields) == 3:
                    if log[fields[0]][fields[1]][fields[2]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                elif len(fields) == 4:
                    if log[fields[0]][fields[1]][fields[2]][fields[3]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                elif len(fields) == 5:
                    if log[fields[0]][fields[1]][fields[2]][fields[3]][fields[4]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                elif len(fields) == 6:
                    if log[fields[0]][fields[1]][fields[2]][fields[3]][fields[4]][fields[5]] != m['conditions'][condition]:
                        match = specialConditions(m['conditions'][condition], match)
                else:
                    raise Exception("Condition references json values which are nested too deeply.")
            except KeyError:
                match = False
        if match is True:
            logger.debug("applying {} map to insertId:{}".format(m['fields']['map'], log['insertId']))
            tracker += 1
            out = parseLog(m, log, format)
            if format == "timesketch":
                writeTimeSketch(out, outputFile)
            else:
                writeCsv(out, writer)
    if match is False and args.mapsonly is False and tracker == 0:
        out = defaultParser(log, format)
        if format == "timesketch":
            writeTimeSketch(out, outputFile)
        else:
            writeCsv(out, writer)
    return


# Function to extract map fields to output fields
# Only supports fields 6 levels deep into a json nest
def parseLog(m, log, format):
    """Parses a log entry.

    Args:
        m: map which was match against a log entry
        log: parsed line of the log file
        format: xlsx, csv or timesketch

    Returns:
        normalised log entry
    """
    output = {}
    for field in m['fields']:
        fieldval = ""
        values = m['fields'][field].split(",")
        if len(values) > 1:  # Multi fields defined for one output
            try:
                for value in values:
                    value = value.strip()
                    if value == "[fulljson]":
                        fieldval += str(log)
                    elif value.startswith("string[") and value.endswith("]"):
                        fieldval += value[7:-1] + " ; "
                    else:
                        tmp = value.split(".")
                        if len(tmp) == 1:
                            fieldval += tmp[0] + ":" + str(log[tmp[0]]) + " ; "
                        elif len(tmp) == 2:
                            fieldval += tmp[0] + "." + tmp[1] + ":" + str(log[tmp[0]][tmp[1]]) + " ; "
                        elif len(tmp) == 3:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]]) + " ; "
                        elif len(tmp) == 4:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + "." + tmp[3] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]]) + " ; "
                        elif len(tmp) == 5:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + "." + tmp[3] + "." + tmp[4] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]]) + " ; "
                        elif len(tmp) == 6:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + "." + tmp[3] + "." + tmp[4] + "." + tmp[5] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]]) + " ; "
                        elif len(tmp) == 7:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + "." + tmp[3] + "." + tmp[4] + "." + tmp[5] + ":" + tmp[6] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]][tmp[6]]) + " ; "
                        elif len(tmp) == 8:
                            fieldval += tmp[0] + "." + tmp[1] + "." + tmp[2] + "." + tmp[3] + "." + tmp[4] + "." + tmp[5] + ":" + tmp[6] + ":" + tmp[7] + ":" + str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]][tmp[6]][tmp[7]]) + " ; "
                        else:
                            fieldval = "<deeply nested json field not supported>"
            except KeyError:
                fieldval += "<blank>"
        else:
            try:
                for value in values:
                    value = value.strip()
                    if value == "[fulljson]":
                        fieldval = str(log)
                    elif value.startswith("string[") and value.endswith("]"):
                        fieldval += value[7:-1]
                    else:
                        tmp = value.split(".")
                        if len(tmp) == 1:
                            fieldval += str(log[tmp[0]])
                        elif len(tmp) == 2:
                            fieldval += str(log[tmp[0]][tmp[1]])
                        elif len(tmp) == 3:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]])
                        elif len(tmp) == 4:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]])
                        elif len(tmp) == 5:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]])
                        elif len(tmp) == 6:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]])
                        elif len(tmp) == 7:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]][tmp[6]])
                        elif len(tmp) == 8:
                            fieldval += str(log[tmp[0]][tmp[1]][tmp[2]][tmp[3]][tmp[4]][tmp[5]][tmp[6]][tmp[7]])
                        else:
                            logger.debug("Error: deeply nested json field not supported for insertId:{}".format(log['insertId']))
                            fieldval = "<deeply nested json field not supported>"
            except KeyError:
                fieldval = "<blank>"
        fieldval = sanitize(fieldval, format)
        if field == "summary":
            field = "message"
        if field == "timestamp":
            field = "datetime"
        if field == "method":
            field = "timestamp_desc"
        output[field] = fieldval
    return output


def process(mapdir, inputFile, format, output):
    maps = []
    # Read map files into global variable 'maps'
    for map in os.listdir(mapdir):
        mapPath = os.path.join(mapdir, map)
        m = readMap(mapPath)
        maps.append(m)

    # Read log file line by line
    with open(inputFile) as f:
        for line in f:
            try:
                log = json.loads(line)
            except json.decoder.JSONDecodeError:
                raise Exception(logger.warning("Failed to load json line. Is the log in \
the formatted correctly (as individual json lines?). If logs are in an array, \
use gcp_log_toolbox 'gcloudformatter' function to convert them. \nInvalid line: \n{}".format(line)))
            # Process each log entry against each map
            processLogEntry(maps, log, format, output)


logger = logging.getLogger(__name__)  # 'root' Logger

if __name__ == "__main__":
    # Argument setup
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="GCP log file (json format)")
    parser.add_argument("-m", "--mapdir", help="Directory containing map files", default="maps")
    parser.add_argument("-o", "--output", help="Output file (TSV)", default=strftime("%Y%m%d-%H%M%S_gcptimeline.tsv", gmtime()))
    parser.add_argument("--format", help="Output format", default="xlsx", choices=['xlsx', 'csv', 'timesketch'])
    parser.add_argument("--mapsonly", help="Only outputs entries that match a map file", action="store_true", default=False)
    parser.add_argument("-v", "--verbose", help="Verbose debug logging", action="store_true", default=False)
    args = parser.parse_args()

    logger = logging.getLogger()  # 'root' Logger
    console = logging.StreamHandler()
    logger.addHandler(console)  # prints to console.
    if args.verbose is True:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.format == "timesketch":
        process(args.mapdir, args.file, args.format, args.output)
    else:
        with open(args.output, 'w', newline='') as csvfile:
            fieldnames = ['insertId', 'timestamp', 'map', 'project', 'account', 'ip', 'userAgent', 'type', 'method', 'severity', 'summary', 'detail']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter='|')
            writer.writeheader()
            process(args.mapdir, args.file, args.format, args.output)
