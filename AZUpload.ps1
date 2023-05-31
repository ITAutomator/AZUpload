#####
## To enable scrips, Run powershell 'as admin' then type
## Set-ExecutionPolicy Unrestricted
#####

#################### Transcript Open
$Transcript = [System.IO.Path]::GetTempFileName()               
Start-Transcript -path $Transcript | Out-Null
#################### Transcript Open

### Main function header - Put RethinkitFunctions.psm1 in same folder as script
$scriptFullname = $PSCommandPath ; if (!($scriptFullname)) {$scriptFullname =$MyInvocation.InvocationName }
$scriptCSV      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ ".csv"  ### replace .ps1 with .csv
$scriptDir      = Split-Path -Path $scriptFullname -Parent
$scriptName     = Split-Path -Path $scriptFullname -Leaf
$scriptBase     = $scriptName.Substring(0, $scriptName.LastIndexOf('.'))
$scriptXML      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ ".xml"  ### replace .ps1 with .xml
if ((Test-Path("$scriptDir\RethinkitFunctions.psm1"))) {Import-Module "$scriptDir\RethinkitFunctions.psm1" -Force} else {write-output "Err 99: Couldn't find RethinkitFunctions.psm1";Start-Sleep -Seconds 10;Exit(99)}
# Get-Command -module RethinkitFunction  ##Shows a list of available functions
############ Globals Load

########### Load From XML
Remove-Variable Globals -ErrorAction SilentlyContinue
$Globals=@{}
$Globals=GlobalsLoad $Globals $scriptXML $false
$GlobalsChng=$false
# Note: these don't really work for booleans or blanks - if the default is false it's the same as not existing
if (-not $Globals.domain)                {$GlobalsChng=$true;$Globals.Add("domain","domain.com")}
if (-not $Globals.SASURL_ingestiondata)  {$GlobalsChng=$true;$Globals.Add("SASURL_ingestiondata","paste from office.com import job")}
if (-not $Globals.job_no)                {$GlobalsChng=$true;$Globals.Add("job_no",1)}
####
if ($GlobalsChng) {GlobalsSave $Globals $scriptXML}
####
#$Globals=@{}
#$Globals["domain"] = "domain.com"
#$Globals["SASURL_ingestiondata"] = "paste from office.com import job"
#$Globals=GlobalsLoad $Globals $scriptXML
###
$stage="1-Stage"
$queue="2-Queue"
$sent="3-Sent"

## https://azure.microsoft.com/en-us/features/storage-explorer
$exe1="C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
##$exe2="C:\Program Files (x86)\Microsoft Azure Storage Explorer\StorageExplorer.exe"

$logdate = get-date -format "yyyy-MM-dd_HH-mm-ss"
WriteText "-----------------------------------------------------------------------------"
WriteText ("$scriptName        Computer:$env:computername User:$env:username PSver:"+($PSVersionTable.PSVersion.Major))
WriteText ""
WriteText "AZ Upload"
WriteText "   Use this to upload PST files to Microsoft 365 Mailboxes."
WriteText "   See Readme.txt before using this."
WriteText "   "
WriteText "   From: You will need to stage some PST files."
WriteText "     To: You will also need a SAS URL from the web site."
WriteText "   "
WriteText "   Download AZCopy: https://aka.ms/downloadazcopy "
WriteText " Check Import jobs: https://compliance.microsoft.com/informationgovernance?viewid=import"
WriteText "-----------------------------------------------------------------------------"
if (-not $Globals["domain"]) {write-output "Blank XML file created. Try running again.";Start-Sleep -Seconds 5;Exit(99)}
If (!(Test-Path $exe1)) {write-output "Err 99: Couldn't find $($exe1)";Start-Sleep -Seconds 10;Exit(99)}
##If (!(Test-Path $exe2)) {write-output "Err 99: Couldn't find $($exe2)";Start-Sleep -Seconds 10;Exit(99)}
New-Item -ItemType Directory -Force -Path ($scriptDir+"\"+$stage) | Out-Null
New-Item -ItemType Directory -Force -Path ($scriptDir+"\"+$queue) | Out-Null
New-Item -ItemType Directory -Force -Path ($scriptDir+"\"+$sent) | Out-Null

If (!(Test-Path ($scriptDir+"\"+$stage))) {write-output "Err 99: Couldn't find $(($scriptDir+"\"+$stage))";Start-Sleep -Seconds 10;Exit(99)}
If (!(Test-Path ($scriptDir+"\"+$queue))) {write-output "Err 99: Couldn't find $(($scriptDir+"\"+$queue))";Start-Sleep -Seconds 10;Exit(99)}
If (!(Test-Path ($scriptDir+"\"+$sent))) {write-output "Err 99: Couldn't find $(($scriptDir+"\"+$sent))";Start-Sleep -Seconds 10;Exit(99)}

#### Get input (pre-loaded from xml)
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
$Globals["domain"] = [Microsoft.VisualBasic.Interaction]::InputBox("Enter domain:", "User", $Globals["domain"])
if ($Globals["domain"] -eq "") {exit}
####
WriteText ("               Domain: " + $Globals["domain"])
GlobalsSave $Globals $scriptXML
#########

########## Show stage
WriteText (" ")
WriteText ("1-Stage Folder:")
$pst_files = @(Get-ChildItem -Path ($scriptDir+"\"+$stage) –File -Recurse -Filter "*.pst") 
$bytestotal = 0
$filecount=0
$fileOK=$true
$filesOK=$true
foreach ($pst_file in $pst_files)
    {
    $fileOK=$true    
    $filecount+=1
    $user=$pst_file.Directory.Name
    $file = $pst_file.Name
    $size = ($pst_file.Length /1GB).ToString("0.0") + " gb"
    $bytestotal += $pst_file.Length
    ## make sure file's parent folder is not stage folder, and grandparent is stage folder
    if ($user -eq $stage)
        { ## parent is $stage folder
        WriteText "$($filecount.tostring("00")). $($size) $($file) [ERR: PST FILES SHOULD BE PLACED IN A FOLDER CALLED <USERNAME>  If you are trying to re-queue, put the files in Queue folder instead]"
        $fileOK=$false
        }
    if ($fileOK)
        {
        if ($pst_file.Directory.Parent.Name -ne $stage)
            { ## grandparent is not $stage folder
            WriteText "$($filecount.tostring("00")). $($size) $($file) [ERR: PST FILES SHOULD BE PLACED IN A FOLDER CALLED <USERNAME> NOT NESTED DEEPER]"
            $fileOK=$false
            }
        }
    if ($fileOK)
        {
        WriteText "$($filecount.tostring("00")). $($size) ($($user)@$($Globals["domain"])) $($file)"
        }
    else
        {
        ##### one bad file means don't proceed later (but keep listing them)
        if ($filesOK)
            {
            $filesOK = $false
            }
        }
    }
$size = ($bytestotal /1GB).ToString("0.0") + " gb"
WriteText "Total: $($size)"

if (-not $filesOK)
    {
    WriteText "[Aborting in 10s]"
    Start-Sleep -Seconds 10;Exit(99)
    }

if ($filecount -gt 0)
    {
    #########
    $message="$filecount files in Stage Folder. Move these to Queue Folder? (No=Abort)"
    $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
    [int]$defaultChoice = 0
    $choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
    if ($choiceRTN -eq 1) { "Aborting";Start-Sleep -Seconds 3;Exit(99)}
    #########
    }

$filecount=0
foreach ($pst_file in $pst_files)
    {
    $filecount+=1
    $user=$pst_file.Directory.Name
    $file = $pst_file.Name
    $size = ($pst_file.Length /1GB).ToString("0.0") + " gb"
    $bytestotal += $pst_file.Length
    move-item $pst_file.FullName ($scriptDir+"\"+$queue+"\"+$user+" "+$file)
    ## Empty folders should get deleted,no?
    if (!(Test-Path -Path ($pst_file.Directory.FullName+"\*")))
        {Remove-Item –path $pst_file.Directory.FullName}
    }

#####################################
WriteText (" ")
WriteText ("2-Queue Folder:")
$pst_files = @(Get-ChildItem -Path ($scriptDir+"\"+$queue) –File -Recurse -Filter "*.pst") 
$bytestotal = 0
$filecount=0
foreach ($pst_file in $pst_files)
    {
    $filecount+=1
    $file = $pst_file.Name
    $size = ($pst_file.Length /1GB).ToString("0.0") + " gb"
    $bytestotal += $pst_file.Length
    $user = $pst_file.Name.split(" ")[0]
    $user += "@"+$Globals["domain"]
    WriteText "$($filecount.tostring("00")). $($size)  [$($user)] $($file)"
    }
$size = ($bytestotal /1GB).ToString("0.0") + " gb"
WriteText "Total: $($size)"

if ($filecount -gt 0)
    {
    #########
    $message="$filecount files in Queue Folder. Upload these to O365? (No=abort)"
    $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
    [int]$defaultChoice = 0
    $choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
    if ($choiceRTN -eq 1) { "Aborting";Start-Sleep -Seconds 3;Exit(99)}
	
	#########
    WriteText "---- The mapping CSV file has a column that indicates whether to import to the the Main mailbox or Archive mailbox."
    $message="Set the CSV to import to the Archive mailbox (Must have archiving ON in EAC)? Y=Archive mailbox N=Main mailbox"
    $choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No")
    [int]$defaultChoice = 0
    $choiceRTN = $host.ui.PromptForChoice($caption,$message, $choices,$defaultChoice)
    if ($choiceRTN -eq 1) {$mboxarch="FALSE"} else {$mboxarch="TRUE"}
	
	
    ######### Create a CSV mapping file
    if ($pst_files.Count -eq 0)
    {
        $map_name = "(none)"
    }
    else
    {
        
        $user = $pst_files[0].Name.split(" ")[0]
        $jobfile  = "job$('{0:d2}' -f $Globals.job_no)-$($user)"
        ###
        $Globals.job_no = $Globals.job_no + 1
        GlobalsSave $Globals $scriptXML
        ###
        $jobfile = [Microsoft.VisualBasic.Interaction]::InputBox("On the website, create an import job with this name:", "Import job ID", $jobfile)
    }
    $csvfile = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+"_"+$logdate+"_$($jobfile).csv"
    $line = "Workload,FilePath,Name,Mailbox,IsArchive,TargetRootFolder,SPFileContainer,SPManifestContainer,SPSiteUrl"
    $line | Out-File -Append $csvfile -encoding ascii

    $filecount=0
    foreach ($pst_file in $pst_files)
        {
        $file = $pst_file.Name
        $user = $pst_file.Name.split(" ")[0]
        $user += "@"+$Globals["domain"]
        $line = "Exchange,,$($file),$($user),$($mboxarch),/,,, "
        $line | Out-File -Append $csvfile -encoding ascii
        }
    WriteText ("--------------------------------------------------------------------------------------")
    WriteText ("CSV Mapping file created: $(Split-Path $csvfile -Leaf) (Edit this as needed and upload to Microsoft)")
    WriteText ("--------------------------------------------------------------------------------------")

    #### Get input (pre-loaded from xml)
    $Globals["SASURL_ingestiondata"] = [Microsoft.VisualBasic.Interaction]::InputBox("Paste the job's SAS URI value here:", "User", $Globals["SASURL_ingestiondata"])
    if ($Globals["SASURL_ingestiondata"] -eq "") {exit}
    ####
    WriteText (" SASURL_ingestiondata: " + $Globals["SASURL_ingestiondata"])
    GlobalsSave $Globals $scriptXML
    #########

    #########
    $o365log = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+"_"+$logdate+"_o365log.txt"
    WriteText (" ")
    WriteText ("Transferring $($size) to O365...(11MB/s = 40G/hour)")
    $params = "/Source:"+'"'+$scriptDir+"\"+$queue+'"'
    $params += " /Dest:"+'"'+$Globals["SASURL_ingestiondata"]+'"'
    $params += " /V:"+'"'+$o365log+'"'
    $params += " /Y"
    ## ------------------------------- Transfer Queue to Office 365
    WriteText ("[WAITING for the launched AZCopy to complete. It's minimized but you can open it. It will close automatically.]")
	WriteText ("Note: the AZCopy program says 'finished:' the whole time it runs (it just means that's how much has finished 'so far')  ")
	WriteText ("  ")
    WriteText ("[Now, tick both boxes on the site and upload the new CSV Mapping file (mentioned above) to Microsoft.]")
    WriteText ("[Keep clicking 'validate' until it succeeds (shortly after files are uploaded]")
    #Write-Host $exe1 $params
    start-process $exe1 $params -Wait -WindowStyle Minimized
    #####################################
    WriteText ("Done sending to O365. Use Azure Storage Explorer to see files (optional)")

    ##################################### Move to Sent
    WriteText (" ")
    WriteText ("3-Sent:")
    
    $filecount=0
    foreach ($pst_file in $pst_files)
        {
        $filecount+=1
        $file = $pst_file.Name
        $size = ($pst_file.Length /1GB).ToString("0.0") + " gb"
        $bytestotal += $pst_file.Length
        $user = $pst_file.Name.split(" ")[0]
        $user += "@"+$Globals["domain"]
        WriteText "$($filecount.tostring("00")). $($size)  [$($user)] $($file)"
        move-item $pst_file.FullName ($scriptDir+"\"+$sent)
        }
    ########
    }
WriteText "------------------------------------------------------------------------------------"
$message ="Done.  Press [Enter] to exit."
WriteText "1- The website will prompt you to upload CSV mapping file (see above)"
WriteText "2- Once the files are validated, the website will show an 'import' button."
WriteText "3- Then the website will process your request over the next few hours."
WriteText "  "
WriteText " https://compliance.microsoft.com/informationgovernance?viewid=import"
WriteText "  "
WriteText " Stages:"
WriteText " Upload Files (this program) > Analysis in progress > Analysis completed"
WriteText " > Import to O365 > Import in progress (long time) > Completed "
WriteText " "
WriteText " Job ID: $($jobfile)"
WriteText "------------------------------------------------------------------------------------"
#################### Transcript Save
Stop-Transcript | Out-Null
$TranscriptTarget = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+"_"+$logdate+"_log.txt"
If (Test-Path $TranscriptTarget) {Remove-Item $TranscriptTarget -Force}
Move-Item $Transcript $TranscriptTarget -Force
#################### Transcript Save
$choices = [System.Management.Automation.Host.ChoiceDescription[]] @("E&xit")
$choices = $host.ui.PromptForChoice("",$message, $choices,0)