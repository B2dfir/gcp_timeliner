import os
import csv
import json
import gcp_timeliner

# To use this file, run the following command from this directory:
# pytest test_functions.py -v


def test_readMap():
    testVal = gcp_timeliner.readMap("./maps/iam_PolicyUpdated.map")
    assert type(testVal) is dict
    assert len(testVal) == 2


def test_santization():
    testString = "', '| ; |': {|}, {|\n|{|\t|"
    testVal = gcp_timeliner.sanitize(testString, False)
    assert len(testVal) == 37


def test_santizationFlat():
    testString = "', '| ; |': {|}, {|\n|{|\t|"
    testVal = gcp_timeliner.sanitize(testString, True)
    assert len(testVal) == 25


def test_parse_log_which_matched_a_map_file():
    logLine = '{"insertId":"-sumke9d4ngo","logName":"projects/peak-empire-243713/logs/cloudaudit.googleapis.com%2Factivity","protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"smash@smashsecurity.com"},"authorizationInfo":[{"granted":true,"permission":"resourcemanager.projects.setIamPolicy","resource":"projects/peak-empire-243713","resourceAttributes":{}},{"granted":true,"permission":"resourcemanager.projects.setIamPolicy","resource":"projects/peak-empire-243713","resourceAttributes":{}}],"methodName":"SetIamPolicy","request":{"@type":"type.googleapis.com/google.iam.v1.SetIamPolicyRequest","policy":{"bindings":[{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.admin"},{"members":["serviceAccount:service-273873411461@compute-system.iam.gserviceaccount.com"],"role":"roles/compute.serviceAgent"},{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.storageAdmin"},{"members":["serviceAccount:273873411461-compute@developer.gserviceaccount.com","serviceAccount:273873411461@cloudservices.gserviceaccount.com"],"role":"roles/editor"},{"members":["user:smash@smashsecurity.com"],"role":"roles/owner"},{"members":["user:smash@smashsecurity.com"],"role":"roles/resourcemanager.organizationAdmin"},{"members":["serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com"],"role":"roles/iam.securityReviewer"}],"etag":"BwWLXEtneGc="},"resource":"peak-empire-243713"},"requestMetadata":{"callerIp":"12.34.56.78","callerSuppliedUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36,gzip(gfe)","destinationAttributes":{},"requestAttributes":{}},"resourceName":"projects/peak-empire-243713","response":{"@type":"type.googleapis.com/google.iam.v1.Policy","bindings":[{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.admin"},{"members":["serviceAccount:service-273873411461@compute-system.iam.gserviceaccount.com"],"role":"roles/compute.serviceAgent"},{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.storageAdmin"},{"members":["serviceAccount:273873411461-compute@developer.gserviceaccount.com","serviceAccount:273873411461@cloudservices.gserviceaccount.com"],"role":"roles/editor"},{"members":["serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com"],"role":"roles/iam.securityReviewer"},{"members":["user:smash@smashsecurity.com"],"role":"roles/owner"},{"members":["user:smash@smashsecurity.com"],"role":"roles/resourcemanager.organizationAdmin"}],"etag":"BwWLbsx/jl4="},"serviceData":{"@type":"type.googleapis.com/google.iam.v1.logging.AuditData","policyDelta":{"bindingDeltas":[{"action":"ADD","member":"serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com","role":"roles/iam.securityReviewer"}]}},"serviceName":"cloudresourcemanager.googleapis.com","status":{}},"receiveTimestamp":"2019-06-16T11:01:17.592409471Z","resource":{"labels":{"project_id":"peak-empire-243713"},"type":"project"},"severity":"NOTICE","timestamp":"2019-06-16T11:01:16.571Z"}'
    mapString = '\
        {\
            "conditions":{\
                "resource.type":"project",\
                "protoPayload.methodName":"SetIamPolicy",\
                "protoPayload.serviceData.policyDelta.bindingDeltas":"*"\
            },\
            "fields":{\
                "insertId":"insertId",\
                "timestamp":"timestamp",\
                "map":"string[iam_policyUpdated]",\
                "project":"resource.labels.project_id",\
                "account":"protoPayload.authenticationInfo.principalEmail",\
                "ip":"protoPayload.requestMetadata.callerIp",\
                "userAgent":"protoPayload.requestMetadata.callerSuppliedUserAgent",\
                "type":"resource.type",\
                "method":"protoPayload.methodName",\
                "severity":"severity",\
                "summary":"protoPayload.serviceData.policyDelta.bindingDeltas",\
                "detail":"[fulljson]"\
            }\
        }'
    logObject = json.loads(logLine)
    m = json.loads(mapString)
    output = gcp_timeliner.parseLog(m, logObject, False)
    assert output['insertId'] == "-sumke9d4ngo"
    assert output['timestamp'] == "2019-06-16T11:01:16.571Z"
    assert output['map'] == "iam_policyUpdated"
    assert output['account'] == "smash@smashsecurity.com"
    assert output['ip'] == "12.34.56.78"
    assert output['userAgent'] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36,gzip(gfe)"
    assert output['type'] == "project"
    assert output['method'] == "SetIamPolicy"
    assert output['severity'] == "NOTICE"
    assert "serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com" in output['summary']
    assert "2019-06-16T11:01:16.571Z" in output['detail']


def test_parse_log_using_default_logic():
    logLine = '{"insertId":"-sumke9d4ngo","logName":"projects/peak-empire-243713/logs/cloudaudit.googleapis.com%2Factivity","protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"smash@smashsecurity.com"},"authorizationInfo":[{"granted":true,"permission":"resourcemanager.projects.setIamPolicy","resource":"projects/peak-empire-243713","resourceAttributes":{}},{"granted":true,"permission":"resourcemanager.projects.setIamPolicy","resource":"projects/peak-empire-243713","resourceAttributes":{}}],"methodName":"SetIamPolicy","request":{"@type":"type.googleapis.com/google.iam.v1.SetIamPolicyRequest","policy":{"bindings":[{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.admin"},{"members":["serviceAccount:service-273873411461@compute-system.iam.gserviceaccount.com"],"role":"roles/compute.serviceAgent"},{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.storageAdmin"},{"members":["serviceAccount:273873411461-compute@developer.gserviceaccount.com","serviceAccount:273873411461@cloudservices.gserviceaccount.com"],"role":"roles/editor"},{"members":["user:smash@smashsecurity.com"],"role":"roles/owner"},{"members":["user:smash@smashsecurity.com"],"role":"roles/resourcemanager.organizationAdmin"},{"members":["serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com"],"role":"roles/iam.securityReviewer"}],"etag":"BwWLXEtneGc="},"resource":"peak-empire-243713"},"requestMetadata":{"callerIp":"12.34.56.78","callerSuppliedUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36,gzip(gfe)","destinationAttributes":{},"requestAttributes":{}},"resourceName":"projects/peak-empire-243713","response":{"@type":"type.googleapis.com/google.iam.v1.Policy","bindings":[{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.admin"},{"members":["serviceAccount:service-273873411461@compute-system.iam.gserviceaccount.com"],"role":"roles/compute.serviceAgent"},{"members":["user:barnabyskeggs@gmail.com"],"role":"roles/compute.storageAdmin"},{"members":["serviceAccount:273873411461-compute@developer.gserviceaccount.com","serviceAccount:273873411461@cloudservices.gserviceaccount.com"],"role":"roles/editor"},{"members":["serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com"],"role":"roles/iam.securityReviewer"},{"members":["user:smash@smashsecurity.com"],"role":"roles/owner"},{"members":["user:smash@smashsecurity.com"],"role":"roles/resourcemanager.organizationAdmin"}],"etag":"BwWLbsx/jl4="},"serviceData":{"@type":"type.googleapis.com/google.iam.v1.logging.AuditData","policyDelta":{"bindingDeltas":[{"action":"ADD","member":"serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com","role":"roles/iam.securityReviewer"}]}},"serviceName":"cloudresourcemanager.googleapis.com","status":{}},"receiveTimestamp":"2019-06-16T11:01:17.592409471Z","resource":{"labels":{"project_id":"peak-empire-243713"},"type":"project"},"severity":"NOTICE","timestamp":"2019-06-16T11:01:16.571Z"}'
    logObject = json.loads(logLine)
    output = gcp_timeliner.defaultParser(logObject, False)
    print(output['detail'])
    assert output['insertId'] == "-sumke9d4ngo"
    assert output['timestamp'] == "2019-06-16T11:01:16.571Z"
    assert output['map'] == "default"
    assert output['account'] == "smash@smashsecurity.com"
    assert output['ip'] == "12.34.56.78"
    assert output['userAgent'] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36,gzip(gfe)"
    assert output['type'] == "project"
    assert output['method'] == "SetIamPolicy"
    assert output['severity'] == "NOTICE"
    assert "serviceAccount:logcollector@peak-empire-243713.iam.gserviceaccount.com" in output['summary']
    assert "projects/peak-empire-243713" in output['detail']


def test_writeTsv():
    with open('unit_test.tsv', 'w', newline='') as csvfile:
        fieldnames = ['insertId', 'timestamp', 'map', 'project', 'account', 'ip', 'userAgent', 'type', 'method', 'severity', 'summary', 'detail']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter='|')
        writer.writeheader()

        out = {}
        out['insertId'] = "a"
        out['timestamp'] = "b"
        out['map'] = "c"
        out['project'] = "d"
        out['account'] = "e"
        out['ip'] = "f"
        out['userAgent'] = "g"
        out['type'] = "h"
        out['method'] = "i"
        out['severity'] = "j"
        out['summary'] = "k"
        out['detail'] = "l"
        gcp_timeliner.writeTsv(out, writer)

    with open('unit_test.tsv') as f:
        contents = f.read()
        assert len(contents) == 112

    os.remove("unit_test.tsv")

