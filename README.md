[comment]: # "Auto-generated SOAR connector documentation"
# Fidelis Network

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Fidelis Cybersecurity  
Product Name: Fidelis Network  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This app integrates with Fidelis Network to execute various investigate and generic actions

# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's fidelisnetwork App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Fidelis Network asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**host\_url** |  required  | string | Host URL \(e\.g\. https\://123E5678\.fclab\.fideliscloud\.com/\)
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list alerts](#action-list-alerts) - List all of the alerts tracked within the enterprise on particular assets and\|or users for the specified time  
[get alert details](#action-get-alert-details) - Gets an alert details from Fidelis Network  
[delete alert](#action-delete-alert) - Delete alerts from Fidelis Network  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

This action logs into the device using a REST API call to check the connection and credentials configured\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list alerts'
List all of the alerts tracked within the enterprise on particular assets and\|or users for the specified time

Type: **investigate**  
Read only: **True**

If the user provides time\-related action parameters, the priority will be given to the \[Time Range\] action parameter and the search will be performed according to its given value\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**column** |  required  | Column for ordering | string | 
**direction** |  required  | Direction of alerts order | string | 
**start\_time** |  optional  | Start time in UTC \(YYYY\-MM\-DD HH\:MM\:SS\) | string | 
**end\_time** |  optional  | End time in UTC \(YYYY\-MM\-DD HH\:MM\:SS\) | string | 
**limit** |  optional  | Specify the maximum number of alerts to return\. You can specify between 1 and 200,000\. \(Default is 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.data\.\*\.aaData\.\*\.ALERT\_ID | numeric |  `alert id` 
action\_result\.data\.\*\.aaData\.\*\.SEVERITY | string | 
action\_result\.data\.\*\.aaData\.\*\.HOST\_IP | string | 
action\_result\.data\.\*\.aaData\.\*\.ALERT\_TYPE | string | 
action\_result\.data\.\*\.aaData\.\*\.ALERT\_TIME | string | 
action\_result\.data\.\*\.aaData\.\*\.SUMMARY | string | 
action\_result\.data\.\*\.toTime | string | 
action\_result\.data\.\*\.fromTime | string | 
action\_result\.data\.\*\.retrieveTime | string | 
action\_result\.data\.\*\.referenceTime | string | 
action\_result\.data\.\*\.cancelled | boolean | 
action\_result\.data\.\*\.totalUnknown | boolean | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.alertTotal | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.parameter\.column | string | 
action\_result\.parameter\.direction | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.start\_time | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alert details'
Gets an alert details from Fidelis Network

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert\_id** |  required  | Alert ID | string |  `alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.alertId | numeric |  `alert id` 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.time | string | 
action\_result\.data\.\*\.summary | string | 
action\_result\.parameter\.alert\_id | string |  `alert id` 
action\_result\.data\.\*\.aggAlertCounts\.\*\.aggAlertId | numeric | 
action\_result\.summary | string | 
action\_result\.data\.\*\.aggAlertCounts\.\*\.alertCount | numeric | 
action\_result\.data\.\*\.anomalyAlertInfo | string | 
action\_result\.data\.\*\.assets\.alertId | numeric | 
action\_result\.data\.\*\.assets\.asset\.assetId | numeric | 
action\_result\.data\.\*\.assets\.asset\.compGroupId | numeric | 
action\_result\.data\.\*\.assets\.asset\.coverageScore | numeric | 
action\_result\.data\.\*\.assets\.asset\.decryptEnd | string | 
action\_result\.data\.\*\.assets\.asset\.decryptStart | string | 
action\_result\.data\.\*\.assets\.asset\.decryptStartUser | string | 
action\_result\.data\.\*\.assets\.asset\.decryptingDuringAlert | boolean | 
action\_result\.data\.\*\.assets\.asset\.importanceScore | numeric | 
action\_result\.data\.\*\.assets\.asset\.insertTime | numeric | 
action\_result\.data\.\*\.assets\.asset\.lastCompId | numeric | 
action\_result\.data\.\*\.assets\.asset\.lastUpdate | numeric | 
action\_result\.data\.\*\.assets\.asset\.riskScore | numeric | 
action\_result\.data\.\*\.assets\.asset\.severityScore | numeric | 
action\_result\.data\.\*\.assets\.asset\.subnetId | numeric | 
action\_result\.data\.\*\.assets\.assetId | numeric | 
action\_result\.data\.\*\.assets\.dstAssetId | numeric | 
action\_result\.data\.\*\.assets\.groupId | numeric | 
action\_result\.data\.\*\.assets\.insertDate | numeric | 
action\_result\.data\.\*\.assets\.lastUpdate | numeric | 
action\_result\.data\.\*\.assets\.otherAsset | string | 
action\_result\.data\.\*\.assets\.otherAssetId | numeric | 
action\_result\.data\.\*\.assets\.senId | numeric | 
action\_result\.data\.\*\.assets\.srcAssetId | numeric | 
action\_result\.data\.\*\.assets\.timestamp | numeric | 
action\_result\.data\.\*\.bit9FindFileUrl | string | 
action\_result\.data\.\*\.clientPort | numeric | 
action\_result\.data\.\*\.collector\.accessible | boolean | 
action\_result\.data\.\*\.collector\.commandPostIp | string | 
action\_result\.data\.\*\.collector\.commandPostName | string | 
action\_result\.data\.\*\.collector\.id | string | 
action\_result\.data\.\*\.collector\.ip | string | 
action\_result\.data\.\*\.collector\.local | boolean | 
action\_result\.data\.\*\.collector\.name | string | 
action\_result\.data\.\*\.collector\.registered | boolean | 
action\_result\.data\.\*\.componentId | numeric | 
action\_result\.data\.\*\.compression | numeric | 
action\_result\.data\.\*\.conclusionAssignee | string | 
action\_result\.data\.\*\.conclusionStatus | string | 
action\_result\.data\.\*\.decodingPath\.clickableDpaths | string | 
action\_result\.data\.\*\.decodingPath\.commandpostIp | string | 
action\_result\.data\.\*\.decodingPath\.decodingPaths | string | 
action\_result\.data\.\*\.decodingPath\.originalAttributes | string | 
action\_result\.data\.\*\.decodingPath\.originalDPath | string | 
action\_result\.data\.\*\.distAlertId\.alertId | numeric | 
action\_result\.data\.\*\.distAlertId\.commandPostId | numeric | 
action\_result\.data\.\*\.distAlertId\.local | boolean | 
action\_result\.data\.\*\.dstCity | string | 
action\_result\.data\.\*\.dstIpInternal | boolean | 
action\_result\.data\.\*\.dstPort | numeric | 
action\_result\.data\.\*\.dstPortDesc | string | 
action\_result\.data\.\*\.dstPortName | string | 
action\_result\.data\.\*\.dstRegion | string | 
action\_result\.data\.\*\.endpointAlert\.alertId | numeric | 
action\_result\.data\.\*\.endpointAlert\.confidence | numeric | 
action\_result\.data\.\*\.endpointAlert\.createDate | numeric | 
action\_result\.data\.\*\.endpointAlert\.eventStatus | numeric | 
action\_result\.data\.\*\.endpointAlert\.eventTime | numeric | 
action\_result\.data\.\*\.endpointAlert\.eventType | numeric | 
action\_result\.data\.\*\.endpointAlert\.insertTime | numeric | 
action\_result\.data\.\*\.endpointAlert\.intelSourceType | numeric | 
action\_result\.data\.\*\.endpointAlert\.lastUpdate | numeric | 
action\_result\.data\.\*\.endpointAlert\.respondeDate | string | 
action\_result\.data\.\*\.endpointAlert\.severity | numeric | 
action\_result\.data\.\*\.endpointAlert\.sourceType | numeric | 
action\_result\.data\.\*\.endpointAlert\.status | numeric | 
action\_result\.data\.\*\.endpointAlert\.userFlagged | numeric | 
action\_result\.data\.\*\.endpointAlert\.validatedDate | string | 
action\_result\.data\.\*\.endpointAlert\.viewed | numeric | 
action\_result\.data\.\*\.entropy | numeric | 
action\_result\.data\.\*\.fidelisScore | numeric | 
action\_result\.data\.\*\.groupId | numeric | 
action\_result\.data\.\*\.hostCity | string | 
action\_result\.data\.\*\.hostInfo\.agentVersion | string | 
action\_result\.data\.\*\.hostInfo\.hostDesc | string | 
action\_result\.data\.\*\.hostRegion | string | 
action\_result\.data\.\*\.ip2IdExist | boolean | 
action\_result\.data\.\*\.ipProtocol | string | 
action\_result\.data\.\*\.pcapUUID | string | 
action\_result\.data\.\*\.pfh | string | 
action\_result\.data\.\*\.pfhFileLength | string | 
action\_result\.data\.\*\.playbookInfo | string | 
action\_result\.data\.\*\.quarantineInfo | string | 
action\_result\.data\.\*\.relSesId | string | 
action\_result\.data\.\*\.rule | string | 
action\_result\.data\.\*\.ruleId | numeric | 
action\_result\.data\.\*\.s1 | string | 
action\_result\.data\.\*\.sensorIp | string | 
action\_result\.data\.\*\.serverPort | numeric | 
action\_result\.data\.\*\.srcCity | string | 
action\_result\.data\.\*\.srcIpInternal | boolean | 
action\_result\.data\.\*\.srcPort | numeric | 
action\_result\.data\.\*\.srcPortDesc | string | 
action\_result\.data\.\*\.srcPortName | string | 
action\_result\.data\.\*\.srcRegion | string | 
action\_result\.data\.\*\.ticket\.assignedGroupId | numeric | 
action\_result\.data\.\*\.ticket\.assignedUserId | numeric | 
action\_result\.data\.\*\.virusTotalDetections | string | 
action\_result\.data\.\*\.vlanId | numeric | 
action\_result\.data\.\*\.workflowAggAlertId | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete alert'
Delete alerts from Fidelis Network

Type: **generic**  
Read only: **False**

This action will always succeed regardless of the input\. This action will fail if <b>alert\_id</b> is not specified\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert\_id** |  required  | Alert IDs \(comma\-separated\) | string |  `alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.alert\_id | string |  `alert id` 
action\_result\.data\.\*\.ALERT\_DATA\.\*\.ALERT\_ID | numeric |  `alert id` 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.Console | string | 
action\_result\.summary\.alert\_ids | string | 