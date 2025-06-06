# SOC-Lab/CyberHomeLab-Microsoft-Sentinel



## Introduction

Deploying Azure Sentinel with a Honeypot for Threat Visualization

A SIEM (Security Information and Event Management) system is a security solution that enables organizations to detect, analyze, and respond to potential threats before they impact business operations. It works by collecting and correlating event log data from various sources across a network, such as firewalls, intrusion detection/prevention systems (IDS/IPS), and identity management tools. This centralized visibility allows security professionals to monitor, prioritize, and remediate threats in real time.

A honeypot is a deliberately vulnerable system designed to attract and study malicious activity within a safe, controlled environment. It serves as a valuable tool for analyzing attacker behavior, identifying new threat vectors, and enhancing cybersecurity strategies.




<h2>Project Overview</h2>

This setup leverages the 30-day free trial offered by Microsoft Sentinel, making it an accessible and cost-effective platform for hands-on cybersecurity training and real-time threat analysis. In this project we will be following a tutorial by <a href="https://www.youtube.com/@JoshMadakor">Josh Madakor</a>

<b>This demo showcases the use of Azure Sentinel (SIEM) integrated with a live Windows VM honeypot to monitor and analyze real-time RDP brute-force attacks from around the globe.


🛠 What It Does

Parses Windows Event Logs for failed RDP login attempts

Uses a PowerShell script to extract attacker IP addresses

Queries a third-party API to retrieve geolocation data

Plots attack sources on an Azure Sentinel map dashboard

🌐 Why It Matters

This project provides hands-on experience with threat detection, log analysis, and real-time SIEM data visualization using cloud-native tools.
</b>
<br />
<br />

<br />
<br />

<p align="center">
  <img src="https://github.com/Jabner98/Sentinel-Lab/assets/112572239/9e8f470c-d18c-4ff3-ad80-dc75a56ea83e"
<!-- <img src="https://i.imgur.com/3d3CEwZ.png" height="85%" width="85%" alt="RDP event fail logs to iP Geographic information"/> --> 
</p>
<details>
 <summary><h3> 📜 PowerShell Script </h3></summary> 
 
```powershell 
# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "d4600b4efdef42b39828f5155041a457"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# This block of code will create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite Loop that keeps checking the Event Viewer logs.
while ($true)
{
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
}
``` 
 
</details>
<h2>Languages Used</h2>

- <b>PowerShell:</b> Extract RDP failed logon logs from Windows Event Viewer 

<h2>Utilities Used</h2>

- <b>ipgeolocation.io:</b> IP Address to Geolocation API
<details>
<summary><h2>Step 01: Create a Microsoft Azure Subscription</h2></summary>
  
1. Navigate to [Microsoft Azure](azure.microsoft.com) and create a free acount
2. Your free account will give you $200 credit for the lab!
</details>

<details>
<summary><h2>Step 02: Deploying a Honeypot</h2></summary>
1. Create a Virtual Machine (VM)

![Creating of VM](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/f9ba427b-663c-488e-b47b-8ae54e9b8e11)

2. Set a user name and password. Remember these as you will need them to log
   into the Virtual Machine
3. Leave Disk as all defaults
4. In the networking section create a new inbound security rule to allow all
   inbound traffic,

![Creating our own Inbound Rule that lets anything in](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/98b2eee5-bd06-4cc7-81f0-344b5ffcfe20)

5. Create your VM
</details>

<details>
<summary><h2>Step 03: Log Analystics Workspace</h2></summary>
Creating LAW.

![Next we create a Log Analytic Workspace](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/9d9ffa00-2929-4f9a-a6cb-7a41423c1746)

</details>

<details>
<summary><h2>Step 04: Microsoft Defender for Cloud</h2></summary>

1. Search for "Microsoft Defender for Cloud"
2. Select "Environment Settings" and under Name select the Log Analytics
   Workspace that you named.
   
![clouddefender](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/cd320253-7e1f-4ae6-8bd6-9e6e074aaac9)

3. Set both Cloud Security Posture Management and Servers to ON. Leave SQL
   servers on machines OFF
   
![turnonclouddefender](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/75a060c9-326d-4731-95ee-ac403385c6b4)

4. Make sure 'All Events' is selected for Data Collection. 
![Turn on some Microsoft Defender settings for resource group](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/de8a4499-76c7-46ee-9150-87bc2700b96a)

5. Don't forget to click "Save"

</details>

<details>
<summary><h2>Step 05: Connect the LAW to the Virtual Machine/ Microsoft Sentinel</h2></summary>

1. Navigate to Log Analystics Workspace and select your virtual machine to connect to the Log Analystics

   ![Connect VM to log anal](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/bc77c08a-fa59-4739-9b53-08cc4999a3f2)

2. Navigate to Microsoft Sentinel and create Microsoft Sentinel.
3. Select your Log Analytics Workspace name
4. Click Add.

![Add Microsoft Sentinel to workspace ](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/c2cd459d-34dd-4170-906d-7baa9aeb4968)

</details>
<details>
<summary><h2>Step 06: Disabling the Firewall in the Windows VM</h2></summary>
  
1. Log into your Windows VM via RDP

  ![Connect to VM](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/1715aabd-7125-463b-8cde-71e491d7dd9f)
  
3. Once logged in type ``wf.msc`` in Start
4. Click on Windows Defender Firewall Properties and turn the firewall off for
   Domain, Private and Public Profiles.

![wfmsc](https://github.com/Jabner98/ActiveDirectoryLab/assets/112572239/dc146035-9f55-4cab-9e19-7c11344ef2ea)

</details>

<details>
<summary><h2>Step 07: Scripting the Security Log Exporter</h2></summary>

1. In the Windows VM download the [Powershell script](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1)
2. Open the script in Powershell ISE
   
<img width="611" alt="image" src="https://github.com/Jabner98/Sentinel-Lab/assets/112572239/4ff366ec-3f02-4ba4-86fa-c9982ef204fd">

4. Save the script. I saved it as "log-exporter"
5. Navigate to https://ipgeolocation.io/ and sign up. You need to get the
   provided api key and paste it into the script.
   
![geolocation](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/e4bda045-1754-4521-8fb5-b25875c696b9)
![Creating API Key for Powershell script](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/4c13ae8e-8253-4688-af2a-6de191fe7dfb)

7. Run the script and navigate to ``C:\ProgramData\failed_rdp``
8. Copy the contents of ``failed_rdp``

ProgramData has been added a failed log file
![ProgramData is been added a failed log file](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/c14d9fb9-7065-4aba-8e33-0873da652fea)

</details>
<details>
<summary><h2>Step 08: Using a custom log in LAW</h2></summary>
  
1. This will allow us to ingest the data that we are getting from the previous script. Navigate to the Log Analytics Workspace
2. Create a custom log by clicking on Tables and New custom log (MMA-based)

![customlogdcr](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/2b0c98f9-500e-4b96-964c-b3976226fd40)

4. Give a name to your custom log
  ![Creating custom log in LAW](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/9723e20d-da6a-4e4a-ba67-748df86e83d2)
5. Click "Next" for Record delimiter
6. Choose Windows for Collection paths and give it the path to the
``failed_rdp.log`` in the Windows VM which would be
``C:\ProgramData\failed_rdp.log``
7. Name your custom log such as ``FAILED_RDP_WITH_GEO``
8. Click Create
![failedrdpwithgeo](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/4793c485-716e-4cbe-b523-fb7db431cc30)

If you don't see results right away, it could take some time for Azure to sync the VM and Log Analytics. Please be patient.
This command shows some failed RDP attempts in LAW. You can see where I purposedly did some test failed logins. 
![Failed_RDP logs in LAW ](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/7b54b5f9-5296-48b0-ba38-d8bb9fe317c6)
</details>
<details>
<summary><h2>Step 09: Mapping the Data in Microsoft Sentinel</h2></summary>
1. Navigate to Microsoft Sentinel > Workbooks > Add workbook
<br />
2. Edit the workbook and remove the default widgets
<br />
3. Add a new query and paste the KQL query below:


![data extraction and map in Sentinel](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/af794089-f4d5-4ed8-bba6-eb3ed6907f8b)

```
FAILED_RDP_WITH_GEO_CL | extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country 
```
4. Run the Query!

   ![Running a script in LAW for the data extraction and map](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/526db8be-b40a-4573-ade7-1c804c60513b)


Visualizing as a Map:
![Visualizing as a Map](https://github.com/Jabner98/Sentinel-Lab/assets/112572239/bc2eb10e-8ebb-42c1-a06c-a2483f0d1849)
</details>

<h2>Several attacks from Ukraine and other countries; Custom logs being output with geodata</h2>

<p align="center">

<img src="https://github.com/Jabner98/Sentinel-Lab/assets/112572239/9673bf85-fd2e-44ce-aa16-5ad6c93c9799">

<!-- <img src="https://i.imgur.com/LhDCRz4.jpeg" height="85%" width="85%" alt="Image Analysis Dataflow"/> -->
</p>

<h2>World map of incoming attacks after a couple of hours (built custom logs including geodata)</h2>

<p align="center">
  <img src="https://github.com/Jabner98/Sentinel-Lab/assets/112572239/2ee9ba5b-e488-4da2-aa01-caf8eda47dc5">

<!-- <img src="https://i.imgur.com/krRFrK5.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>  -->
</p>


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
