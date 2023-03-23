# Cribl Edge Microsoft Sentinel Security and Windows Event Pack
----

This pack is designed to work with the Cribl Edge Windows Event fowarder and will convert Security events into the Sentinel SecurityEvent (https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) schema and Application and System based events into the Sentinel WindowsEvent based schema and tables (https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent). It does NOT yet as of (3/24/23) work with the Cribl Stream Windows Event Forwarder. 


## Requirements Section

Before you begin, ensure that you have met the following requirements:

* Setup a Microsoft destination write both the SecurityEvent and WindowsEvent native tables by configuring a webhook outlined in guide here: https://docs.cribl.io/stream/usecase-azure-webhook/
* Deploy the Cribl Edge Windows event forwarder.

## How it works
* Ingest the raw JSON log from the CSV event forwarder.
* Convert the JSON based windows event from the Cribl Edge forwarder into an XML by using the field mappings from win_mappings.csv.
* Rename fields to Pascal Casing SecurityEvent and WindowsEvent by using their respective mapping files.
* Drop any fields that are not part of WindowsEvent or SecurityEvent schema.
* Numerify any values that are numbers. 

## Sample outputs

Original Security Event payload from Cribl Edge Windows Event forwarder: 

```
{
  "_raw": "{\"Id\":4634,\"Version\":0,\"Qualifiers\":null,\"Level\":0,\"Task\":12545,\"Opcode\":0,\"Keywords\":-9214364837600034816,\"RecordId\":343310,\"ProviderName\":\"Microsoft-Windows-Security-Auditing\",\"ProviderId\":\"54849625-5478-4994-a5ba-3e3b0328c30d\",\"LogName\":\"Security\",\"ProcessId\":724,\"ThreadId\":4104,\"MachineName\":\"EC2AMAZ-A7J1A2F\",\"UserId\":null,\"TimeCreated\":\"\\/Date(1679330336354)\\/\",\"ActivityId\":null,\"RelatedActivityId\":null,\"ContainerLog\":\"security\",\"MatchedQueryIds\":[],\"Bookmark\":{},\"LevelDisplayName\":\"Information\",\"OpcodeDisplayName\":\"Info\",\"TaskDisplayName\":\"Logoff\",\"KeywordsDisplayNames\":[\"Audit Success\"],\"Properties\":[{\"Value\":\"S-1-5-21-581362713-338647900-3507251088-500\"},{\"Value\":\"Administrator\"},{\"Value\":\"EC2AMAZ-A7J1A2F\"},{\"Value\":3165134},{\"Value\":3}],\"Message\":\"An account was logged off.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-581362713-338647900-3507251088-500\\r\\n\\tAccount Name:\\t\\tAdministrator\\r\\n\\tAccount Domain:\\t\\tEC2AMAZ-A7J1A2F\\r\\n\\tLogon ID:\\t\\t0x304BCE\\r\\n\\r\\nLogon Type:\\t\\t\\t3\\r\\n\\r\\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.\"}",
  "source": "Security",
  "host": "EC2AMAZ-A7J1A2F",
  "_time": 1679330336.354,
  "cribl_breaker": "windows event logs"
}
```

Converted Security Event into Sentinel WindowsEvent schema.
```
{
  "Level": 0,
  "Task": 12545,
  "Opcode": 0,
  "RecordId": 343310,
  "ProcessId": 724,
  "MachineName": "EC2AMAZ-A7J1A2F",
  "RelatedActivityId": null,
  "LevelDisplayName": "Information",
  "OpcodeDisplayName": "Info",
  "TimeGenerated": "2023-03-20T16:38:56.354000000Z",
  "EventData": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='1679330336354'/><EventRecordID>343310</EventRecordID><Correlation/><Execution ProcessID='724' ThreadID='4104'/><Channel>Security</Channel><Computer>EC2AMAZ-A7J1A2F</Computer><Security/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-581362713-338647900-3507251088-500</Data><Data Name='TargetUserName'>Administrator</Data><Data Name='TargetDomainName'>EC2AMAZ-A7J1A2F</Data><Data Name='TargetLogonId'>3165134</Data><Data Name='LogonType'>3</Data></EventData></Event>",
  "TargetUserSid": "S-1-5-21-581362713-338647900-3507251088-500",
  "TargetUserName": "Administrator",
  "TargetDomainName": "EC2AMAZ-A7J1A2F",
  "TargetLogonId": 3165134,
  "LogonType": 3,
  "Computer": "EC2AMAZ-A7J1A2F",
  "EventID": 4634,
  "EventSourceName": "Microsoft-Windows-Security-Auditing",
  "Channel": "security",
  "DisplayName": "Logoff",
  "SourceSystem": "Cribl Edge Windows Event Forwarder",
  "Activity": "4634 - An account was logged off.",
  "TargetAccount": "EC2AMAZ-A7J1A2F\\Administrator",
  "Type": "SecurityEvent",
  "cribl_pipe": "cribl_edge_windows_security_events"
}
```

Sample Window Event payload from Cribl Windows Event Edge Forwarder: 

```
{
  "_raw": "{\"Id\":10000,\"Version\":0,\"Qualifiers\":null,\"Level\":4,\"Task\":0,\"Opcode\":0,\"Keywords\":-9223372036854775808,\"RecordId\":7191,\"ProviderName\":\"Microsoft-Windows-RestartManager\",\"ProviderId\":\"0888e5ef-9b98-4695-979d-e92ce4247224\",\"LogName\":\"Application\",\"ProcessId\":3684,\"ThreadId\":9056,\"MachineName\":\"EC2AMAZ-T19PLRU\",\"UserId\":{\"BinaryLength\":28,\"AccountDomainSid\":{\"BinaryLength\":24,\"AccountDomainSid\":\"S-1-5-21-1025632903-1663302900-376929966\",\"Value\":\"S-1-5-21-1025632903-1663302900-376929966\"},\"Value\":\"S-1-5-21-1025632903-1663302900-376929966-500\"},\"TimeCreated\":\"\\/Date(1677711803989)\\/\",\"ActivityId\":null,\"RelatedActivityId\":null,\"ContainerLog\":\"Application\",\"MatchedQueryIds\":[],\"Bookmark\":{},\"LevelDisplayName\":\"Information\",\"OpcodeDisplayName\":\"Info\",\"TaskDisplayName\":null,\"KeywordsDisplayNames\":[],\"Properties\":[{\"Value\":2},{\"Value\":\"\\/Date(1677711803984)\\/\"}],\"Message\":\"Starting session 2 - ?2023?-?03?-?01T23:03:23.984850300Z.\"}",
  "source": "in_win_event_logs",
  "host": "EC2AMAZ-T19PLRU",
  "_time": 1677711803.989,
  "cribl_breaker": [
    "Windows Event Logs:regex",
    "noBreak1MB"
  ]
}
```

Example Output of WindowsEvent:
```
{
  "Version": 0,
  "Task": 0,
  "Opcode": 0,
  "Keywords": -9223372036854776000,
  "TimeGenerated": "2023-03-01T23:03:23.989000000Z",
  "RawEventData": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RestartManager' Guid='{0888e5ef-9b98-4695-979d-e92ce4247224}'/><EventID>10000</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='1677711803989'/><EventRecordID>7191</EventRecordID><Correlation/><Execution ProcessID='3684' ThreadID='9056'/><Channel>Application</Channel><Computer>EC2AMAZ-T19PLRU</Computer><Security/></System><EventData><Data Name='ExtensibleModulePath'>2</Data><Data Name='ErrorCode'>/Date(1677711803984)/</Data></EventData></Event>",
  "Computer": "EC2AMAZ-T19PLRU",
  "EventID": 10000,
  "EventLevel": 4,
  "EventRecordId": 7191,
  "Provider": "Microsoft-Windows-RestartManager",
  "SystemProcessId": 3684,
  "SystemThreadId": 9056,
  "Channel": "Application",
  "EventLevelName": "Information",
  "Type": "WindowsEvent",
  "EventData": null,
  "cribl_pipe": "cribl_edge_windows_events"
}
```

## Using The Pack

Here's the instructions to use the pack: 

1. Add the pack to your Cribl Stream or Edge instance via github or file upload.
2. Setup a Cribl Edge Windows Event fowarder on your Windows host(s). 
3. Configure both a WindowsEvent and SecurityEvent webhook destination outlined in the guide here: https://docs.cribl.io/stream/usecase-azure-webhook/.
3. Create two routes so we can handle both Security and Application/System based events coming from the Cribl Edge forwarder:
   1. SecurityEvent Sentinl Route: 
    * Filter: ```_raw.indexOf("\"ContainerLog\":\"security\"") > -1 || _raw.indexOf("\"ProviderName\":\"Microsoft-Windows-Security-Auditing\"")```.
    * Source: Cribl Edge Windows Event fowarders source.
    * Pack: microsoft-sentinel-windows-events-cribl-edge
    * Destination: Cribl Sentinel SecurityEvent destination webhook. 
   2. WindowsEvent route: 
    * Filter: ```_raw.indexOf("\"ContainerLog\":\"Application\"") > -1 || _raw.indexOf("\"ContainerLog\":\"System\"") > -1```.
    * Source: Cribl Edge Windows Event fowarders source.
    * Pack: microsoft-sentinel-windows-events-cribl-edge
    * Destination: Cribl Sentinel WindowsEvent destination webhook. 


## TODO
* Convert RawEventData XML payload into 'dynamic' type. 
* More testing and validation of events. 
* Make this pack work with the Cribl Stream Windows Edge Event Forwarder. 

## Release Notes

### Version 0.0.1 - 2023-03-22
This is the first release. Don't laugh.


## Contact
To contact us please email kbrunette@cribl.io.


## License
TThis Pack uses the following license: [`Apache 2.0`](https://www.apache.org/licenses/LICENSE-2.0).
