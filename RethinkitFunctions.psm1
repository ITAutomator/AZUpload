########################################################################
# RethinkitFunctions.psm1  
# 
# New Master Location: Rethinkit\Staff - General\Programming.Powershell
# Old Master Location: S:\Apps Cloud\!New PC Setup\Scripts
#
# Notes
# You can't use Write-Output in lines with exit since write-output returns the output to the caller.
# Use write-host or WriteText on those lines.
#
# Version History
# 2020-11-01
# - Import-Vault
# - Export-Vault
# 2020-02-20
# - Update Master Location
# 2020-02-09
# - AskChoice
# 2020-02-07
# - O365Connect fixed error msg
# 2020-01-12
# - FilenameVersioned
# 2019-12-22
# - Set-CredentialInFile
# - Get-CredentialInFile
# - VarExists
# 2019-11-25
# - Screenshot
# - Get-PublicIPInfo
# 2019-10-19
# - Get-IniFile, Show-IniFile
# 2019-10-08
# - TimeSpanAsText
# 2019-08-16
# - AppVerb error trapping
# - GlobalsLoad warning messages
# 2019-04-23
# - O365Connect function
# 2018-10-21
# - LeftChars function added
# 2018-10-13
# - Changed GlobalsLoad Write-host to Write-warning
# - Changed PauseTimed to prompt from command line rather than dialog
# 2018-10-02
# - Added Encrypt
# 2018-09-06
# - Fixed bug in GlobalsLoad with init (warning message was inadvertently returned in the stream)
# 2018-07-17
# - Fixed sample code in GlobalsLoad
# 2017-04-25
# - CommandLineSplit fixes
# - Get-FileMetaData fixed in case no property name
# 2017-11-02
# - CommandLineSplit
# 2016-09-24
# - AppNameVerb
# 2016-05-22
# - Changed RegSet to create key if doesn't exist
# 
########################################################################
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

#### To use these functions in your .ps1 file
# Put this .psm1 in the same folder as the .ps1
# Then put this code at the top of your .ps1
####
<# 
######################
## Main Procedure
######################
###
## To enable scrips, Run powershell 'as admin' then type
## Set-ExecutionPolicy Unrestricted
###
### Main function header - Put RethinkitFunctions.psm1 in same folder as script
$scriptFullname = $PSCommandPath ; if (!($scriptFullname)) {$scriptFullname =$MyInvocation.InvocationName }
$scriptXML      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ ".xml"  ### replace .ps1 with .xml
$scriptDir      = Split-Path -Path $scriptFullname -Parent
$scriptName     = Split-Path -Path $scriptFullname -Leaf
$scriptBase     = $scriptName.Substring(0, $scriptName.LastIndexOf('.'))
if ((Test-Path("$scriptDir\RethinkitFunctions.psm1"))) {Import-Module "$scriptDir\RethinkitFunctions.psm1" -Force} else {write-host "Err: Couldn't find RethinkitFunctions.psm1";return}
# Get-Command -module RethinkitFunction  ##Shows a list of available functions
######################
#>
#
########################################################################
Function WriteText ($line)
    {  ## Use this instead of Write-Host Write-Output if you can.  Write-Output writes better to programs that capture output.
    Write-Output $line
    }

Function Pause ($Message="Press any key to continue.")
    {
    If($psISE)
        {
        $S=New-Object -ComObject "WScript.Shell"
        $B=$S.Popup($Message,0,"Script Paused",0)
        Return
		}
	Else
		{
		Write-Host -NoNewline $Message
		$I=16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183
		While ($K.VirtualKeyCode -Eq $Null -Or $I -Contains $K.VirtualKeyCode)
			{
			$K=$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			}
		Write-Host "(OK)"
		}
    }

Function PauseTimed ()
	# Example:
	# PauseTimed -quiet:$quiet -secs 3
    {
    Param ## provide a comma separated list of switches
	    (
	    [switch]  $quiet  ## continue without input
        ,[int]    $secs=1 ## if quiet, will pause and display a note, use -secs=0 for no display
        ,[string] $prompt ## optional
	    )
    if ($quiet)
        {
        if (!($prompt))
            {
            $prompt = "<< Pausing for "+ $secs + " secs >>"
            }
        if ($secs -gt 0)
            {
            WriteText $prompt
            Start-Sleep -Seconds $secs
            }
        }
    else
        {
        If($psISE)
            {
            ## IDE mode (development mode doesn't allow ReadKey)
            if (!($prompt)) {$prompt = "<Press Enter to continue>"}
            Read-Host $prompt
            #Write-Host $prompt
            #$S=New-Object -ComObject "WScript.Shell"
            #$B=$S.Popup($prompt,0,"Script Paused",0)
            }
        else
            {
            if (!($prompt)) {$prompt = "Press any key to continue (Ctrl-C to abort)..."}
            Write-Host -NoNewline $prompt
            # $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            # Write-Host
            $I=16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183
            While ($K.VirtualKeyCode -Eq $Null -Or $I -Contains $K.VirtualKeyCode)
                {
                $K=$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                ## write-host "keycode " $K.VirtualKeyCode
                }
			Write-Host "(OK)"
            }
        }
    }

Function GlobalsSave ($Globals, $scriptXML)
    {
    Export-Clixml -InputObject $Globals -Path $scriptXML
    }

Function GlobalsLoad ($Globals, $scriptXML, $force=$true)
    <#
    .SYNOPSIS
    Reads or Creates an XML settings file
    .DESCRIPTION
    
    .PARAMETER Globals
    Array of variables definded by $Globals = @{} 
    .PARAMETER scriptXML
    File to store globals
    .PARAMETER force
    Create XML with defaults if not found
    .EXAMPLE
    ## Globals Init with defaults                                            
    $Globals = @{}                                                           
    $Globals.Add("PersistentVar1","Testing")                                 
    $Globals.Add("PersistentVar2",17983)                                     
    $Globals.Add("PersistentVar3",(Get-Date))                                
    ### Reads or Creates an XML settings file
	$Globals = GlobalsLoad $Globals $scriptXML				                                         
    ## Globals used                                                          
    $Globals["PersistentVar1"] = "hello"                                     
    $Globals["PersistentVar2"] = "hello"                                     
    $Globals["PersistentVar3"] = "hello"                                     
    write-host ("PersistentVar1        : " + ($Globals["PersistentVar1"]))   
    write-host ("PersistentVar2        : " + ($Globals["PersistentVar2"]))   
    write-host ("PersistentVar3        : " + ($Globals["PersistentVar3"]))   
    ## Globals Persist to XML                                                
    GlobalsSave  $Globals $scriptXML
    #>
    {
    if (-not ($Globals))
        {
        $ErrOut=211; $ErrMsg="No Globals provided" ; Write-Host ("Err "+$ErrOut+" ("+$MyInvocation.MyCommand+"): "+ $ErrMsg);Start-Sleep -Seconds 3; Exit($ErrOut)
        }
    if (-not ($scriptXML))
        {
        $ErrOut=212; $ErrMsg="No scriptXML provided" ; Write-Host ("Err "+$ErrOut+" ("+$MyInvocation.MyCommand+"): "+ $ErrMsg);Start-Sleep -Seconds 3; Exit($ErrOut)
        }
    if (-not(Test-Path($scriptXML)))
        {
        ## Save Globals to XML
        
        if ($force)
            {
            Write-Warning ("Creating a new file with default values: "+$scriptXML)
    	    Export-Clixml -InputObject $Globals -Path $scriptXML
            }
        else
            {
            Write-Warning "Couldn't find settings file. (Use '-force=`$true' option to create one)"
            }
        }
    else
        {
        ## Load Globals from XML
        $Globals = Import-Clixml -Path $scriptXML
        }
    return $Globals
    }

Function PowershellVerStop ($minver)
    {
    if ($PSVersionTable.PSVersion.Major -lt $minver)
        {
        $ErrMsg ="Requires Powershell v$minver"
        $ErrMsg+=" : You have Powershell v"+$PSVersionTable.PSVersion.Major
        $ErrMsg="Requires Powershell v$minver"
        $ErrOut=316;Write-Host ("Err "+$ErrOut+" ("+$MyInvocation.MyCommand+"): "+ $ErrMsg);Start-Sleep -Seconds 3; Exit($ErrOut)
        }
    }

 Function IsAdmin() 
    {
    <#
    .SYNOPSIS
    Checks if the running process has elevated priviledges.
    .DESCRIPTION
    To get elevation with powershell, right-click the .ps1 and run as administrator - or run the ISE as administrator.
    .PARAMETER computername
    Purpose of parameter computername goes here.
    .PARAMETER filePath
    .EXAMPLE
    if (-not(IsAdmin))
        {
        write-host "No admin privs here, run this elevated"
        return
        }
    #>
    $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    $IsAdmin=$prp.IsInRole($adm)
    $IsAdmin
    }

Function CreateLocalUser($username, $password, $desc, $computername, $GroupsList="Administrators")
    {
    <#
    .SYNOPSIS
    Creates a local admin user.
    .PARAMETER computername
    Computer where account is to be created, uses $env:computername if none provided.
    .PARAMETER username
    Account name to create
    .PARAMETER desc
    Description max is 48 chars
    .EXAMPLE
    $un="AdminUser"
    $ds="Replacement account for Administrator"
    $pw="ij;wiejn2-38974"
    CreateUser $un $pw $ds $pc "Administrators"
    #>
    if (-not ($computername)) {$computername=$env:computername}
    $adcomputer = [ADSI]"WinNT://$computername,computer"
    WriteText ("Create:"+$username.PadRight(20)+"["+$desc+"]")
    $localUsers = $adcomputer.Children | where {$_.SchemaClassName -eq 'user'}  | % {$_.name[0].ToString()}
    if ($localUsers -contains $username)
        {
        WriteText ("   [Delete existing user]")
        $adcomputer.delete("user", $username)
        }
    $user = $adcomputer.Create("user", $username)
    $user.SetPassword($password)
    $user.SetInfo()
    $user.description = $desc
    $user.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
    $user.SetInfo()
    $GroupsList.split(',') | ForEach-Object  {
        $Group="$_"
		if ($Group -ne "")
			{
			$adgroup = [ADSI]("WinNT://$computername/$Group,group")
			$adgroup.add("WinNT://$username,user")
			WriteText ("   Add to Group: $Group")
			}
        }
    }

Function EncryptString ($StringToEncrypt, $Key)
    {
    if (-not ($Key)) ## default to a simple key
        {
        [Byte[]] $key = (1..16)
        }
    $EncryptedSS = ConvertTo-SecureString -AsPlainText -Force -String $StringToEncrypt
    $Encrypted = ConvertFrom-SecureString -key $key -SecureString $EncryptedSS
    return $Encrypted
}

Function EncryptStringSecure ($StringToEncrypt)
    {
    $EncryptedSS = ConvertTo-SecureString -AsPlainText -Force -String $StringToEncrypt
    $Encrypted = ConvertFrom-SecureString -SecureString $EncryptedSS
    return $Encrypted
}


Function DecryptString ($StringToDecrypt, $Key)
    {
    if (-not ($Key)) ## default to a simple key
        {
        [Byte[]] $key = (1..16)
        }
    $StringToDecryptSS= ConvertTo-SecureString -Key $key -String $StringToDecrypt
    $Decrypted=(New-Object System.Management.Automation.PSCredential 'N/A', $StringToDecryptSS).GetNetworkCredential().Password
    return $Decrypted
}

Function DecryptStringSecure ($StringToDecrypt)
    {
    $StringToDecryptSS= ConvertTo-SecureString -String $StringToDecrypt
    $Decrypted=(New-Object System.Management.Automation.PSCredential 'N/A', $StringToDecryptSS).GetNetworkCredential().Password
    return $Decrypted
}

Function RegGetX ($keymain, $keypath, $keyname)
### DOESN'T WORK - WITH EXPANDABLE ENV VARS - IT PRE-EXPANDS THEM
#########
## $ver=RegGet "HKCR" "Word.Application\CurVer"
#########
    {
    Switch ($keymain)
    {
        "HKCU" {If (-Not (Test-Path -path HKCU:)) {New-PSDrive -Name HKCU -PSProvider registry -Root Hkey_Current_User | Out-Null}}
        "HKCR" {If (-Not (Test-Path -path HKCR:)) {New-PSDrive -Name HKCR -PSProvider registry -Root Hkey_Classes_Root | Out-Null}}
    }
    $keymainpath = $keymain + ":\" + $keypath
    ## check if key even exists
    if (Test-Path $keymainpath)
        {
        ## check if value exists
        if ([string]::IsNullOrEmpty($keyname)) {$keyname="(default)"}
        if (Get-ItemProperty -Path $keymainpath -Name $keyname -ea 0)
            {
            $result=(Get-ItemProperty -Path $keymainpath -Name $keyname).$keyname
            }
	    }
    $result
    }


Function RegGet ($keymain, $keypath, $keyname)
#########
## $ver=RegGet "HKCR" "Word.Application\CurVer"
#########
    {
    $result = ""
    Switch ($keymain)
        {
            "HKLM" {$RegGetregKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keypath, $false)}
            "HKCU" {$RegGetregKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keypath, $false)}
            "HKCR" {$RegGetregKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($keypath, $false)}
        }
    if ($RegGetregKey)
        {
        $result=$RegGetregKey.GetValue($keyname, $null, "DoNotExpandEnvironmentNames")
        }
    $result
    }

Function RegSet ($keymain, $keypath, $keyname, $keyvalue, $keytype)
#########
## RegSet "HKCU" "Software\Microsoft\Office\15.0\Common\General)" "DisableBootToOfficeStart" 1 "dword"
## RegSet "HKCU" "Software\Microsoft\Office\15.0\Word\Options" "PersonalTemplates" "%appdata%\microsoft\templates" "ExpandString"
#########
{
    ## Convert keytype string to accepted values keytype = String, ExpandString, Binary, DWord, MultiString, QWord, Unknown
    if ($keytype -eq "REG_EXPAND_SZ") {$keytype="ExpandString"}
    if ($keytype -eq "REG_SZ") {$keytype="String"}

    Switch ($keymain)
    {
        "HKCU" {If (-Not (Test-Path -path HKCU:)) {New-PSDrive -Name HKCU -PSProvider registry -Root Hkey_Current_User | Out-Null}}
    }
    $keymainpath = $keymain + ":\" + $keypath
    ## check if key even exists
    if (!(Test-Path $keymainpath))
        {
        ## Create key
        New-Item -Path $keymainpath -Force | Out-Null
        }
    ## check if value exists
    if (Get-ItemProperty -Path $keymainpath -Name $keyname -ea 0)
        ## change it
        {Set-ItemProperty -Path $keymainpath -Name $keyname -Type $keytype -Value $keyvalue}
    else
        ## create it
        {New-ItemProperty -Path $keymainpath -Name $keyname -PropertyType $keytype -Value $keyvalue | out-null }
}

Function RegSetCheckFirst ($keymain, $keypath, $keyname, $keyvalue, $keytype)
#########
## RegSetCheckFirst "HKCU" $Regkey $Regval $Regset $Regtype
#########
{
    $x=RegGet $keymain $keypath $keyname
    if ($x -eq $keyvalue)
        {$ret="[Already set] $keyname=$keyvalue ($keymain\$keypath)"}
    else
        {
        if (($x -eq "") -or ($x -eq $null)) {$x="(null)"}
        RegSet $keymain $keypath $keyname $keyvalue $keytype
        $ret="[Reg Set] $keyname=$keyvalue [was $x] ($keymain\$keypath)"
        }
    $ret
}


Function RegDel ($keymain, $keypath, $keyname)
#########
## RegDel "HKCU" "Software\Microsoft\Office\15.0\Common\General)" "DisableBootToOfficeStart"
#########
{
    Switch ($keymain)
    {
        "HKCU" {If (-Not (Test-Path -path HKCU:)) {New-PSDrive -Name HKCU -PSProvider registry -Root Hkey_Current_User | Out-Null}}
    }
    $keymainpath = $keymain + ":\" + $keypath
    ## check if key even exists
    if (Test-Path $keymainpath)
        {
        ## check if value exists
        if (Get-ItemProperty -Path $keymainpath -Name $keyname -ea 0)
            ## remove it
            {Remove-ItemProperty -Path $keymainpath -Name $keyname}
		}
}

Function PathtoExe ($Exe)
	{
	$ver=RegGet "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$Exe"
	## winword.exe
	## powerpnt.exe
	## excel.exe
	## outlook.exe
	if ($ver)
        {$ver}
    else
        {"(na:$Exe)"}
	}

Function AppVerb ($PathtoExe, $VerbStartsWith)
	#########
	## AppVerb "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" "Pin"
    ## $PathtoExe = PathtoExe "winword.exe"
    ## WriteText (AppVerb $PathtoExe "Pin")
	## Verbs: Open Properties Pin Unpin
	#########
	{
	$sa = new-object -c shell.application
	$pn = $sa.namespace("").parsename($PathtoExe)
	##Uncomment to show verbs
	##$pn.Verbs() | Select-Object @{Name="Verb";Expression={$_.Name.replace('&','')}}
	##
	$verb = $pn.Verbs() | where-object {$_.Name.Replace('&','') -like ($VerbStartsWith+'*')}
	if ($verb) 
		{
        Try {
            $verb.DoIt()
            "[OK] (" + $verb.Name.Replace('&','') + ") " + $PathtoExe
            }
        Catch{
            "[ERR] (" + $verb.Name.Replace('&','') + ") " + $PathtoExe +" "+ $_.Exception.Message
            }
		}
	else
		{
		"[APP ACTION NOT FOUND] (" + $VerbStartsWith + ") " + $PathtoExe
		}
	
	}

Function AppNameVerb ($AppName, $VerbStartsWith)
	#########
    ## AppNameVerb APPNAME VERB
    ## AppNameVerb (Shows all apps)
    ## AppNameVerb APPNAME (Shows all verbs)
    ## Ex:
	## AppNameVerb "Word 2016" "Pin to start"
    ## AppNameVerb "Microsoft Edge" "Unpin from Start"
    ## AppNameVerb "Microsoft Edge" "Unpin from taskbar"

    ## WriteText (AppVerb $PathtoExe "Pin")
	## Verbs: Open Properties "Pin to Start" "Unpin from Start"
	#########
	{
    $Apps =(New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()
    if (!($AppName))
        { ## Show List of apps
        $Apps | Sort-Object Name | Select-Object Name, Path
        }
    else
        {
        $App= $Apps | ?{$_.Name -eq $AppName}
        if ((!$App))
            {"[APP NOT FOUND] (" + $AppName + ") Call 'AppNameVerb' with no params to show valid apps."}
        else
            {
            if (!($VerbStartsWith))
                { ## Show List of verbs
                $App.Verbs() | Select-Object @{Name="Verb";Expression={$_.Name.replace('&','')}}
                }
            else
                {
                $verb = $App.Verbs() | where-object {$_.Name.Replace('&','') -like ($VerbStartsWith+'*')}
                if (!($verb))
                    {"[APP ACTION NOT FOUND] ("+ $AppName + " > " + $VerbStartsWith + ") Call 'AppNameVerb APPNAME' with no verb to show valid verbs."}
                else
                    {
                    Try {
                        $verb.DoIt()
                        "[OK] (" + $verb.Name.Replace('&','') + ") " + $AppName
                        }
                    Catch{
                        "[ERR] (" + $verb.Name.Replace('&','') + ") " + $AppName +" "+ $_.Exception.Message
                        }
                    }
                }
            }
        }
    $remaining=[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Apps)
    Remove-Variable Apps
    ####

	}

Function AppRemove ($Appname)
	#########
	## Get-AppxPackage -AllUsers | Sort-Object Name  | Select-Object Name  ## Shows packages
    ##     Remove-AppxPackage
	## Get-AppxProvisionedPackage -online| Sort-Object DisplayName | Select-Object DisplayName
    ##     Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName    | where {$_.Displayname -eq $App}).PackageName
    ## $Appname="Microsoft.MicrosoftSolitaireCollection"
    ## Get-AppxPackage -AllUsers "$Appname" | Remove-AppxPackage
    ## Get-AppxProvisionedPackage -online  | where {$_.Displayname -eq $Appname}
    ## $Packagename = "Microsoft.MicrosoftSolitaireCollection_3.7.1041.0_neutral_~_8wekyb3d8bbwe"
    ## Remove-AppxProvisionedPackage -Online -PackageName $Packagename
	## AppRemove "*CandyCrush*"
	## AppRemove "*phone*"
	## AppRemove "*zune*"
	## AppRemove "*SolitaireCollection*"
	## AppRemove "*XboxApp*"
	## AppRemove "*Twitter*"
	#########
	{  ## $Appname="Microsoft.XboxApp"
	$AppXNames=(Get-AppxPackage -AllUsers "$Appname")
 	If ($AppXNames)
		{
        $AppXName=$AppXNames[0].Name
        WriteText "[APP REMOVE] $AppXName"
		Get-AppxPackage "$Appname" | Remove-AppXPackage
        $ProvisonedPackages=Get-AppxProvisionedPackage -online  | where {$_.Displayname -eq $AppXName}
        if ($ProvisonedPackages)
            {
            $PackageName=$ProvisonedPackages[0].PackageName
            WriteText "[PACKAGE REMOVE] $PackageName"
            Remove-AppXProvisionedPackage -Online -PackageName $PackageName
            }
		}
	else
		{
		WriteText "[APP NOT FOUND] $Appname"
		}
	}

# ----------------------------------------------------------------------------- 
# Script: Get-FileMetaDataReturnObject.ps1 
# Author: ed wilson, msft 
# Date: 01/24/2014 12:30:18 
# Keywords: Metadata, Storage, Files 
# comments: Uses the Shell.APplication object to get file metadata 
# Gets all the metadata and returns a custom PSObject 
# it is a bit slow right now, because I need to check all 266 fields 
# for each file, and then create a custom object and emit it. 
# If used, use a variable to store the returned objects before attempting 
# to do any sorting, filtering, and formatting of the output. 
# To do a recursive lookup of all metadata on all files, use this type 
# of syntax to call the function: 
# Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName 
# note: this MUST point to a folder, and not to a file. 
# ----------------------------------------------------------------------------- 
Function Get-FileMetaData 
{ 
  <# 
   .Synopsis 
    This function gets file metadata and returns it as a custom PS Object  
   .Description 
    This function gets file metadata using the Shell.Application object and 
    returns a custom PSObject object that can be sorted, filtered or otherwise 
    manipulated. 
   .Example 
    Get-FileMetaData -folder "e:\music" 
    Gets file metadata for all files in the e:\music directory 
   .Example 
    Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName 
    This example uses the Get-ChildItem cmdlet to do a recursive lookup of  
    all directories in the e:\music folder and then it goes through and gets 
    all of the file metada for all the files in the directories and in the  
    subdirectories.   
   .Example 
    Get-FileMetaData -folder "c:\fso","E:\music\Big Boi" 
    Gets file metadata from files in both the c:\fso directory and the 
    e:\music\big boi directory. 
   .Example 
    $meta = Get-FileMetaData -folder "E:\music" 
    This example gets file metadata from all files in the root of the 
    e:\music directory and stores the returned custom objects in a $meta  
    variable for later processing and manipulation. 
   .Parameter Folder 
    The folder that is parsed for files  
   .Notes 
    NAME:  Get-FileMetaData 
    AUTHOR: ed wilson, msft 
    LASTEDIT: 01/24/2014 14:08:24 
    KEYWORDS: Storage, Files, Metadata 
    HSG: HSG-2-5-14 
   .Link 
     Http://www.ScriptingGuys.com 
 #Requires -Version 2.0 
 #> 
 Param([string[]]$folder) 
 foreach($sFolder in $folder) 
  { 
   $a = 0 
   $objShell = New-Object -ComObject Shell.Application 
   $objFolder = $objShell.namespace($sFolder) 
 
   foreach ($File in $objFolder.items()) 
    {  
     $FileMetaData = New-Object PSOBJECT 
      for ($a ; $a  -le 266; $a++) 
       {  
         if($objFolder.getDetailsOf($File, $a)) 
           { 
             $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))  = 
                        $($objFolder.getDetailsOf($File, $a)) } 
            $FileMetaData | Add-Member $hash 
            $hash.clear()  
           } #end if 
       } #end for  
     $a=0 
     $FileMetaData 
    } #end foreach $file 
  } #end foreach $sfolder 
} #end Get-FileMetaData

Function Get-OSVersion
	{
    # returns
    # $OS[0] 10.0
    # and 
    # $OS[1] Windows 10
    # 
	$ver=[environment]::OSVersion.Version
	##(Get-WmiObject Win32_OperatingSystem).version
	##(Get-CimInstance Win32_OperatingSystem).version
	$verbase = "" + $ver.Major + "." + $ver.Minor
	$verdesc = switch ($verbase)
		{
		"10.0" {"Win 10"}
		"6.3"  {"Win 8.1"}
		"6.2"  {"Win 8"}
		"6.1"  {"Win 7"}
		"6.0"  {"Win Vista"}
		"5.1"  {"Win XP"}
		default {"(Get-OSVersion) Unknown OS " + $verbase}
		}
	$verbase
	$verdesc
	}

Function ConvertPSObjectToHashtable
### Example Use:
# $results = Invoke-WebRequest $url -Body $payload -UseBasicParsing -Method Post | ConvertFrom-Json
# $LPResults = $results | ConvertPSObjectToHashtable
# $users = $LPResults.Users.GetEnumerator()
# foreach ($user in $users)
###

{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}

Function CommandLineSplit ($line)
    {  ## Splits a commandline [1 string] into a exe path and an argument list [2 string].
    # [in] MSIExec.exe sam tom ann  [out] MSIExec.exe , sam tom ann
    # $exeargs = CommandLineSplit "msiexec.exe /I {550E322B-82B7-46E3-863A-14D8DB14AD54}"
    # write-host $exeargs[0] $exeargs[1]
    # Here are the command line types that can be dealt with 
    #
    #$line = 'C:\ProgramFiles\LastPass\lastpass_uninstall.com'
    #$line = 'msiexec /qb /x {3521BDBD-D453-5D9F-AA55-44B75D214629}'
    #$line = 'msiexec.exe /I {550E322B-82B7-46E3-863A-14D8DB14AD54}'
    #$line = '"c:\my path\test.exe'
    #$line = '"c:\my path\test.exe" /arg1 /arg2'
    #
    $return_exe= ""
    $return_args = ""
    $quote = ""
    if ($line.startswith("""")) {$quote=""""}
    if ($line.startswith("'")) {$quote="'"}
    ## did we find a quote of either type
    if ($quote -eq "")  ## not a quoted string
        {
        $exepos=$line.IndexOf(".exe")
        if($exepos -eq -1) 
            #non quoted and no .exe , just find space
            {
            $spacepos=$line.IndexOf(" ")
            if($spacepos -eq -1)
                {#non quoted and no .exe,no space: no args
                #C:\ProgramFiles\LastPass\lastpass_uninstall.com
                $return_exe= $line
                $return_args=""
                }
            else
                {#non quoted and no .exe,with a space: split on space
                #msiexec /qb /x {3521BDBD-D453-5D9F-AA55-44B75D214629}  
                #javaw -jar "C:\Program Files (x86)\Mimo\MimoUninstaller.jar" -f -x 
                $return_exe= $line.Substring(0,$spacepos)
                $return_args=$line.Substring($spacepos+1)
                }
            }
        else
            {#non quoted with .exe , split there
            # C:\Program Files\Realtek\Audio\HDA\RtlUpd64.exe -r -m -nrg2709                                            
            # msiexec.exe /I {550E322B-82B7-46E3-863A-14D8DB14AD54} : 2nd most normal case
            $return_exe= $line.Substring(0,$exepos+4)
            $return_args=$line.Substring($exepos+4)
            }
        }
    else  ## has a quote, find closing quote and strip
        {
        $quote2=$line.IndexOf($quote,1)
        if($quote2 -eq -1)
            { # no close quote, no args: likely a publisher error
            #"c:\my path\test.exe
            $return_exe= $line.Substring(1)
            $return_args=""
            }
        else
            { # strip quotes and the rest are args: most normal case
            #"c:\my path\test.exe" /arg1 /arg2
            $return_exe= $line.Substring(1,$quote2-1)
            # check if args exist and return them
            if ($line.length -gt $quote2+1)
                {
                $return_args=$line.Substring($quote2+2)
                }
            }
        }
    #Return values, removing any spaces in front or at end
    $return_exe.trim()
    $return_args.Trim()
    }

Function Get-MsiDatabaseProperties () { 
    <# 
    .SYNOPSIS 
    This function retrieves properties from a Windows Installer MSI database. 
    .DESCRIPTION 
    This function uses the WindowInstaller COM object to pull all values from the Property table from a MSI 
    .EXAMPLE 
    Get-MsiDatabaseProperties 'MSI_PATH' 
    .PARAMETER FilePath 
    The path to the MSI you'd like to query 
    #> 
    [CmdletBinding()] 
    param ( 
    [Parameter(Mandatory=$True, 
        ValueFromPipeline=$True, 
        ValueFromPipelineByPropertyName=$True, 
        HelpMessage='What is the path of the MSI you would like to query?')] 
    [IO.FileInfo[]]$FilePath 
    ) 
 
    begin { 
        $com_object = New-Object -com WindowsInstaller.Installer 
    } 
 
    process { 
        try { 
 
            $database = $com_object.GetType().InvokeMember( 
                "OpenDatabase", 
                "InvokeMethod", 
                $Null, 
                $com_object, 
                @($FilePath.FullName, 0) 
            ) 
 
            $query = "SELECT * FROM Property" 
            $View = $database.GetType().InvokeMember( 
                    "OpenView", 
                    "InvokeMethod", 
                    $Null, 
                    $database, 
                    ($query) 
            ) 
 
            $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) 
 
            $record = $View.GetType().InvokeMember( 
                    "Fetch", 
                    "InvokeMethod", 
                    $Null, 
                    $View, 
                    $Null 
            ) 
 
            $msi_props = @{} 
            while ($record -ne $null) { 
                $prop_name = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 1) 
                $prop_value = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 2) 
                $msi_props[$prop_name] = $prop_value 
                $record = $View.GetType().InvokeMember( 
                    "Fetch", 
                    "InvokeMethod", 
                    $Null, 
                    $View, 
                    $Null 
                ) 
            } 
 
            $msi_props 
 
        } catch { 
            throw "Failed to get MSI file version the error was: {0}." -f $_ 
        } 
    } 
}

function Get-FileMetaData2
    {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias(‘FullName’, ‘PSPath’)]
        [string[]]$Path
        )
 
    begin
        {
        $oShell = New-Object -ComObject Shell.Application
        }
 
    process
        {
        $Path | ForEach-Object
            {
            if (Test-Path -Path $_ -PathType Leaf)
                {
                $FileItem = Get-Item -Path $_
                $oFolder = $oShell.Namespace($FileItem.DirectoryName)
                $oItem = $oFolder.ParseName($FileItem.Name)
                $props = @{}
                0..287 | ForEach-Object
                    {
                    $ExtPropName = $oFolder.GetDetailsOf($oFolder.Items, $_)
                    $ExtValName = $oFolder.GetDetailsOf($oItem, $_)
               
                    if (-not $props.ContainsKey($ExtPropName) -and ($ExtPropName -ne ''))
                        {
                        $props.Add($ExtPropName, $ExtValName)
                        }
                     }
                New-Object PSObject -Property $props
                }
            }
 
        }
 
    end 
        {
        $oShell = $null
        }
    }


# ----------------------------------------------------------------------------- 
# Script: Get-FileMetaDataReturnObject.ps1 
# Author: ed wilson, msft 
# Date: 01/24/2014 12:30:18 
# Keywords: Metadata, Storage, Files 
# comments: Uses the Shell.APplication object to get file metadata 
# Gets all the metadata and returns a custom PSObject 
# it is a bit slow right now, because I need to check all 266 fields 
# for each file, and then create a custom object and emit it. 
# If used, use a variable to store the returned objects before attempting 
# to do any sorting, filtering, and formatting of the output. 
# To do a recursive lookup of all metadata on all files, use this type 
# of syntax to call the function: 
# Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName 
# note: this MUST point to a folder, and not to a file. 
# ----------------------------------------------------------------------------- 
Function Get-FileMetaDataFromFolders 
{ 
  <# 
   .Synopsis 
    This function gets file metadata (from an array of folders) and returns it as a custom PS Object  
   .Description 
    This function gets file metadata using the Shell.Application object and 
    returns a custom PSObject object that can be sorted, filtered or otherwise 
    manipulated. 
   .Example 
    Get-FileMetaData -folder "e:\music" 
    Gets file metadata for all files in the e:\music directory 
   .Example 
    Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName 
    This example uses the Get-ChildItem cmdlet to do a recursive lookup of  
    all directories in the e:\music folder and then it goes through and gets 
    all of the file metada for all the files in the directories and in the  
    subdirectories.   
   .Example 
    Get-FileMetaData -folder "c:\fso","E:\music\Big Boi" 
    Gets file metadata from files in both the c:\fso directory and the 
    e:\music\big boi directory. 
   .Example 
    $meta = Get-FileMetaData -folder "E:\music" 
    This example gets file metadata from all files in the root of the 
    e:\music directory and stores the returned custom objects in a $meta  
    variable for later processing and manipulation. 
   .Parameter Folder 
    The folder that is parsed for files  
   .Notes 
    NAME:  Get-FileMetaData 
    AUTHOR: ed wilson, msft 
    LASTEDIT: 01/24/2014 14:08:24 
    KEYWORDS: Storage, Files, Metadata 
    HSG: HSG-2-5-14 
   .Link 
     Http://www.ScriptingGuys.com 
 #Requires -Version 2.0 
 #> 
 Param([string[]]$folder) 
 foreach($sFolder in $folder) 
  { 
   $a = 0 
   $objShell = New-Object -ComObject Shell.Application 
   $objFolder = $objShell.namespace($sFolder) 
 
   foreach ($File in $objFolder.items()) 
    {  
     $FileMetaData = New-Object PSOBJECT 
      for ($a ; $a  -le 266; $a++) 
       {  
         if($objFolder.getDetailsOf($File, $a)) 
           { 
             $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))  = 
                   $($objFolder.getDetailsOf($File, $a)) } 
            $FileMetaData | Add-Member $hash 
            $hash.clear()  
           } #end if 
       } #end for  
     $a=0 
     $FileMetaData 
    } #end foreach $file 
  } #end foreach $sfolder 
} #end Get-FileMetaData


Function Get-FileMetaData
# Returns meta data of a file
# Example returing ID 0,34,156
# $meta =  Get-FileMetaData $installer[0].Fullname (0,34,156)
# Example showing all IDs (might be slow)
# $meta =  Get-FileMetaData $installer[0].Fullname (0..288) $true
# WriteText ( $meta.'File description' + " (v"+ $meta.'File version' + ") "  + $meta.Name)
{ 
Param([string] $path, $propnums=(0..255), $showids = $false) 

$shell = New-Object -COMObject Shell.Application
$folder = Split-Path $path
$file = Split-Path $path -Leaf
$shellfolder = $shell.Namespace($folder)
$shellfile = $shellfolder.ParseName($file)
$FileMetaData = New-Object PSOBJECT 
ForEach ($propX In $propnums)
    {  
    $propval = $shellfolder.getDetailsOf($shellfile, $propX)
    if($propval) 
        { 
        $propnam = $shellfolder.getDetailsOf($shellfolder.items, $propX)
        if ($propnam -eq "")
            {
            $propnam = "{none}"
            }									 
        if ($showids) { write-host $propX.tostring() $propnam ":" $propval }
        ##
        $hash += @{ $propnam  =  $propval }
        $FileMetaData | Add-Member $hash
        $hash.clear()
        ##
        } 
    else
        {
        # write-host $propX.tostring()
        }
    }
$FileMetaData 
}

Function LeftChars 
{   #### Return Leftmost N chars
    Param([string] $text, [Int] $Length=100) 
    $left = $text.SubString(0, [math]::min($Length,$text.length))
    $left
}

Function O365Connect
{
    Param (
         [string] $scriptXML
        ,[String] $Domain =""
    )
    # $O365_PasswordXML   = $scriptDir+ "\O365_Password.xml"
    # Write-Host "XML: $($O365_PasswordXML)"
    # ## ----------Connect/Save Password
    # $PSCred=O365Connect($O365_PasswordXML)
    #
    #
    ## Globals Init with defaults                                            
    $O365Globals = @{}
    $O365Globals.Add("CreateDate",(Get-Date).ToString("yyyy-MM-dd hh:mm:ss"))
    $O365Globals.Add("LastUsedDate",(Get-Date).ToString("yyyy-MM-dd hh:mm:ss")+" ["+${env:COMPUTERNAME}+" "+${env:USERNAME}+"]")
    ## Globals Load from XML                                                 
    $O365Globals=GlobalsLoad $O365Globals $scriptXML $false

    #if ($passes.Count -eq 1)     {        $admin_creds = $passes[0]    }
    #else     {        ### pick one        $admin_creds = $passes[0]    }
    ## 
    if (!(Get-Command "Connect-MSOLService" -errorAction SilentlyContinue))
    {
        Write-host "WARNING: Your powershell environment doesn't have the command Connect-MSOLService."
        Write-Host "Step 1. Search google for 'microsoft online services sign-in assistant' and install it."
		Write-Host "Step 2. From a Powershell (as admin) prompt: Install-Module MSOnline"
		Write-Host "(Closing in 10s)"
		Start-Sleep 10
        exit
    }
    ###
    $done=$true
    Do
    { ######### Choice loop

        #### Gets a list of eligibal passwords for this user/pc combination
        $passes = @($O365Globals.Passwords | Where-Object {($_.hostname -eq ${env:COMPUTERNAME}) -and ($_.username -eq ${env:USERNAME})})
        ###
        $choice_list = @() # $null
        $choice_default = ""
        $i = 1
        Write-Host "-----------------"
        Write-Host "Select an account (last used $($O365Globals.LastUsedDate))"
        Write-Host "-----------------"
        ForEach ($pass in $passes)
        {
            $choice_obj=@(
                [pscustomobject][ordered]@{
                number=$i
                adminuser=$pass.adminuser
                adminpass=$pass.adminpass
                }
            )
            $choice_descrip = ""
            if ($domain -ne "")
            { #domain match requested
                if ($pass.adminuser.Split("@")[1].ToLower() -eq $Domain.ToLower())
                { #match
                    $choice_default = $i
                    $choice_descrip = " [match for '$($Domain)']"
                } #match
            } #domain match requested
            Write-Host "  $($i)]  $($choice_obj.adminuser) $($choice_descrip)"
            ### append object
            $i+=1
            $choice_list +=$choice_obj
        }
        $i-=1
        Write-Host "-----------------"
        #### Get input
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
		if ($i -eq 0)
			{$msg = "Enter a username`r`n[(blank) to Cancel]"}
		else
			{$msg = "Enter a number (1-$($i)) <OR> a username`r`n[Xn to delete entry (n), (blank) to Cancel]"}
        Write-Host $msg
        $choice = [Microsoft.VisualBasic.Interaction]::InputBox($msg, "User", $choice_default)
        ###
        $O365Globals.LastUsedDate = (Get-Date).ToString("yyyy-MM-dd hh:mm:ss")+" ["+${env:COMPUTERNAME}+" "+${env:USERNAME}+"]"
        if ($choice -eq "") {write-host "Aborted by user.";return $null}
        if ($choice -match '^\d+$')
        { ### picked a number to use
            $pass = @($choice_list | Where-Object {($_.number -eq $choice)})
            if (!($pass))
            { ## invalid number
                Write-Host "[INVALID CHOICE]"
                $done=$false
            }
            else
            { ## try the selected password
                Try
                {
                    ### ConvertTo-SecureString: SecureString_Plaintext >> SecureString (PSCreds use SecureString, XML stores SecureString_Plaintext)
                    $pass_secstr = ConvertTo-SecureString $pass.adminpass -ErrorAction Stop
                    $PSCred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $pass.adminuser , $pass_secstr -ErrorAction Stop
                    # -------------------------------------------------------
                    # Create creds based on saved password using DPAPI.  
                    # DPAPI is Microsoft's data protection method to store passwords at rest.  The files are only decryptable on the machine / user that created them.
                    # 
                    # Decrypt methods below are OK for debugging, as long as the decrypted values aren't saved
                    #
                    # Decrypt method 1
                    # [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($pass_secstr_plaintext))
                    #
                    # Decrypt method 2
                    # $PSCred.GetNetworkCredential().password
                    # -------------------------------------------------------
                    # Try to connect using these credentials
                    Connect-MSOLService -Credential $PSCred -ErrorAction Stop
                    $done=$true
                    ## Globals Persist to XML
                    GlobalsSave $O365Globals $scriptXML
                }
                Catch
                {
                    Write-Warning "[Invalid or no password value for [$($pass.adminuser)]. Perhaps delete it and try again."
                    $done=$false
                }
            } ## try the selected password
        } ### picked a number to use
        elseif ($choice.Substring(0,1).tolower() -eq "x")
        { ### picked a number to delete
            $choice=$choice.substring(1)
            $pass = @($choice_list | Where-Object {($_.number -eq $choice)})
            if (!($pass))
            { ## invalid delete number
                Write-Host "[INVALID DELETE CHOICE]"
                $done=$false
            } ## invalid delete number
            else
            { ## valid delete number
                Write-Host "[DELETING $($choice): $($pass.adminuser)]"
                # Return everything BUT an exact match (deletes old password if it exists)
                $new_passes = @($O365Globals.Passwords | Where-Object {-not (($_.hostname -eq ${env:COMPUTERNAME}) -and ($_.username -eq ${env:USERNAME}) -and ($_.adminuser -eq $pass.adminuser))})
                $O365Globals.Passwords = $new_passes
                #
                $done=$false
                ## Globals Persist to XML
                GlobalsSave $O365Globals $scriptXML
            } ## valid delete number
        } ### picked a number to delete
        else
        { ### New adminuser
            $PSCred = Get-Credential -Message "Enter O365 Admin Password" -UserName $choice
            if (!($PSCred))
            { # no creds
                Write-Host "No creds entered"
                $done=$false
            } # no creds
            else
            { # got creds
                Write-Host "Trying to connect to MS Online using $($PSCred.UserName)"
                Try
                {
                    # -------------------------------------------------------
                    # Try to connect using these credentials
                    Connect-MSOLService -Credential $PSCred -ErrorAction Stop
                    $done=$true
                }
                Catch
                {
                    Write-Warning "[Invalid or no password value for [$($PSCred.UserName)]. Perhaps delete it and try again."
                    $done=$false
                }
                if ($done)
                    { # they worked
                    #### Save globals
                    ## Create a new object based on user entries
                    $obj = [pscustomobject]@{                       
                            adminuser = $PSCred.UserName
                            adminpass = ($PSCred.Password | ConvertFrom-SecureString)
                            hostname  = ${env:COMPUTERNAME}
                            username  = ${env:USERNAME}
                            }
                    if ($O365Globals.Passwords)
                    { # old passwords found
                        # Return everything BUT an exact match (deletes old password if it exists)
                        $new_passes = @($O365Globals.Passwords | Where-Object {-not (($_.hostname -eq ${env:COMPUTERNAME}) -and ($_.username -eq ${env:USERNAME}) -and ($_.adminuser -eq $obj.adminuser)) })
                        $O365Globals.Passwords = $new_passes
                        #
                        #add this password
                        $O365Globals.Passwords+=$obj
                    } # old passwords found
                    else
                    { # no old passwords found
                        $O365Globals.Passwords=@()
                        $O365Globals.Passwords+=$obj
                    } # no old passwords found
                    ## Globals Persist to XML
                    GlobalsSave $O365Globals $scriptXML
                    } # they worked
            } # got creds
        } ### New adminuser
    } Until ($done) ######### Choice loop
    # Return credentials
    $PSCred
}

Function DatedFileName ($Logfile)
{
    # Ex: $x = DatedFileName ($logfile)
    # In  C:\Logfile\Logfile.txt
    # Out C:\Logfile\Logfile_2019-08-16_v01.txt
    # Out C:\Logfile\Logfile_2019-08-16_v02.txt
    $Return = $Logfile

    #[System.IO.Path] | Get-Member -Static
    #[System.IO.Path]::GetDirectoryName("c:\jason\jason.txt")
    #[System.IO.Path]::GetFileNameWithoutExtension("c:\jason\jason.txt")
    #[System.IO.Path]::GetExtension("c:\jason\jason.txt")
    #[System.IO.Path]::Combine("c:\jason" , "jason.txt")

    $ext = [System.IO.Path]::GetExtension($Logfile)
    $DatePart=(Get-Date).ToString("yyyy-mm-dd")
    $ver=0

    Do
    { ## keep looking until File 'Logfile_2019-08-16_vNN.txt' doesn't exist
        $ver+=1
        $Thisfile = [System.IO.Path]::GetFileNameWithoutExtension($Logfile) #Logfile
        $Thisfile += "_" + $DatePart #_2019-08-16
        $Thisfile += "_v" + $ver.ToString("##") #_v01
        if ($ext -ne "")
        {
            $Thisfile += $ext  #.csv
        }
        $Return = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($Logfile) , $Thisfile)
    }
    Until (!(Test-Path $Return )) 
    $Return ## Return this path
}

Function FilenameVersioned ($MyFile)
{
    # Ex: $x = FilenameVersioned ($MyFile)
    # In  C:\MyFile\MyFile.txt
	# Out C:\MyFile\MyFile.txt
    # Out C:\MyFile\MyFile_v01.txt
    # Out C:\MyFile\MyFile_v02.txt
    $Return = $MyFile

    #[System.IO.Path] | Get-Member -Static
    #[System.IO.Path]::GetDirectoryName("c:\jason\jason.txt")
    #[System.IO.Path]::GetFileNameWithoutExtension("c:\jason\jason.txt")
    #[System.IO.Path]::GetExtension("c:\jason\jason.txt")
    #[System.IO.Path]::Combine("c:\jason" , "jason.txt")

    $ext = [System.IO.Path]::GetExtension($MyFile)
    $ver=0

    While (Test-Path $Return)
    { ## keep looking until File 'MyFile_vNN.txt' doesn't exist
        $ver+=1
        $Thisfile = [System.IO.Path]::GetFileNameWithoutExtension($MyFile) #MyFile
        $Thisfile += "_v" + $ver.ToString("##") #_v01
        $Thisfile += $ext  #.csv
        $Return = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($MyFile) , $Thisfile)
    }
    $Return ## Return this path
}

Function TimeSpanAsText 
{   ### TimeSpanAsText([timespan]::fromseconds(50000)
    Param([timespan] $ts) 
    #
    $result = ""
    if ($ts.Days -gt 0) {$result+=" $($ts.Days)d"}
    if ($ts.Hours -gt 0) {$result+=" $($ts.Hours)h"}
    if ($ts.Minutes -gt 0) {$result+=" $($ts.Minutes)m"}
    if ($ts.Seconds -gt 0) {$result+=" $($ts.Seconds)s"}
    $result = $result.Trim()
    # Return result
    $result
}

Function FromUnixTime 
{   ### FromUnixTime(1570571081) returns 10/08/2019 @ 9:44pm (UTC)
    Param([Int32] $secsfrom1970) 
    #
    [datetime]$origin = '1970-01-01 00:00:00'
    $result = $origin.AddSeconds($secsfrom1970)
    # Return result
    $result
}

Function Get-IniFile {
    <#
    .SYNOPSIS
    Read an ini file.
    
    .DESCRIPTION
    Reads an ini file into a hash table of sections with keys and values.
    
    .PARAMETER filePath
    The path to the INI file.
    
    .PARAMETER anonymous
    The section name to use for the anonymous section (keys that come before any section declaration).
    
    .PARAMETER comments
    Enables saving of comments to a comment section in the resulting hash table.
    The comments for each section will be stored in a section that has the same name as the section of its origin, but has the comment suffix appended.
    Comments will be keyed with the comment key prefix and a sequence number for the comment. The sequence number is reset for every section.
    
    .PARAMETER commentsSectionsSuffix
    The suffix for comment sections. The default value is an underscore ('_').
    .PARAMETER commentsKeyPrefix
    The prefix for comment keys. The default value is 'Comment'.
    
    .EXAMPLE
    Get-IniFile /path/to/my/inifile.ini
    
    .NOTES
    The resulting hash table has the form [sectionName->sectionContent], where sectionName is a string and sectionContent is a hash table of the form [key->value] where both are strings.
    This function is largely copied from https://stackoverflow.com/a/43697842/1031534. An improved version has since been pulished at https://gist.github.com/beruic/1be71ae570646bca40734280ea357e3c.
    #>
    
    param(
        [parameter(Mandatory = $true)] [string] $filePath,
        [string] $anonymous = 'NoSection',
        [switch] $comments,
        [string] $commentsSectionsSuffix = '_',
        [string] $commentsKeyPrefix = 'Comment'
    )

    $ini = @{}
    switch -regex -file ($filePath) {
        "^\[(.+)\]$" {
            # Section
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
            if ($comments) {
                $commentsSection = $section + $commentsSectionsSuffix
                $ini[$commentsSection] = @{}
            }
            continue
        }

        "^(;.*)$" {
            # Comment
            if ($comments) {
                if (!($section)) {
                    $section = $anonymous
                    $ini[$section] = @{}
                }
                $value = $matches[1]
                $CommentCount = $CommentCount + 1
                $name = $commentsKeyPrefix + $CommentCount
                $commentsSection = $section + $commentsSectionsSuffix
                $ini[$commentsSection][$name] = $value
            }
            continue
        }

        "^(.+?)\s*=\s*(.*)$" {
            # Key
            if (!($section)) {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $name, $value = $matches[1..2]
            $ini[$section][$name] = $value
            continue
        }
    }

    return $ini
}

# $ini | Show-IniFile
Function Show-IniFile {
        [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline)] [hashtable] $data,
        [string] $anonymous = 'NoSection'
    )
    process {
        $iniData = $_

        if ($iniData.Contains($anonymous)) {
            $iniData[$anonymous].GetEnumerator() |  ForEach-Object {
                Write-Output "$($_.Name)=$($_.Value)"
            }
            Write-Output ''
        }

        $iniData.GetEnumerator() | ForEach-Object {
            $sectionData = $_
            if ($sectionData.Name -ne $anonymous) {
                Write-Output "[$($sectionData.Name)]"

                $iniData[$sectionData.Name].GetEnumerator() |  ForEach-Object {
                    Write-Output "$($_.Name)=$($_.Value)"
                }
            }
            Write-Output ''
        }
    }
}

Function Screenshot($jpg_path)
{
    Add-type -AssemblyName System.Drawing
 
    # Return resolution
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top
 
    # Create graphic
    $screenshotImage = New-Object System.Drawing.Bitmap $Width, $Height
 
    # Create graphic object
    $graphicObject = [System.Drawing.Graphics]::FromImage($screenshotImage)
 
    # Capture screen
    $graphicObject.CopyFromScreen($Left, $Top, 0, 0, $screenshotImage.Size)
 
    # Save to file - Saves to c:\temp
    $screenshotImage.Save($jpg_path)
    
    # Dispose
    $screenshotImage.Dispose()
    $graphicObject.Dispose()

    # Report
    $return="Screenshot: [$($width) x $($height)] '$($jpg_path)'"
    $return
}

Function Get-PublicIPInfo
{
#
# ip       : 24.105.149.82
# hostname : rrcs-24-105-149-82.nys.biz.rr.com
# city     : Gramercy Park
# region   : New York
# country  : US
# loc      : 40.7375,-73.9861
# org      : AS12271 Charter Communications Inc
# postal   : 10010
# timezone : America/New_York
# readme   : https://ipinfo.io/missingauth
#
    $return = Invoke-RestMethod http://ipinfo.io/json
    $return
}

Function Get-CredentialInFile
{
    Param (
         [string] $credentialXML
        ,[String] $service ="smtp"
		,[String] $logon ="logon" 
		,[boolean] $set=$false
        ,[String] $password ="" 
    )
   
	## ## EXAMPLE
	## ##### Read any existing password
    ## $smtp_pass = Get-CredentialInFile "$($scriptDir)\Credentials.xml" "SyncPlayerSMTP" $Globals.email_smtp_user
    ## $smtp_pass = Set-CredentialInFile "$($scriptDir)\Credentials.xml" "SyncPlayerSMTP" $Globals.email_smtp_user $smtp_pass
    ## ####
    ## $msg = new-object Net.Mail.MailMessage 
    ## $smtp = new-object Net.Mail.SmtpClient($Globals.email_smtp_server)
    ## $smtp.Port=$Globals.email_smtp_port
    ## $smtp.EnableSsl = $Globals.email_smtp_ssl
    ## $smtp.Credentials = New-Object System.Net.NetworkCredential($Globals.email_smtp_user, $smtp_pass)
    ## ####
    ## $msg.From = $Globals.email_from
    ## $Globals.email_to.Split(";") | ForEach-Object {$msg.To.Add($_)}
    ## $msg.BodyEncoding = [system.Text.Encoding]::Unicode 
    ## $msg.SubjectEncoding = [system.Text.Encoding]::Unicode 
    ## $msg.IsBodyHTML = $true
    ## ##########
    ## $msg.Subject = "$($scriptName) Test"
    ## $msg.Body = "<code>   $($version) 
    ## </br> 
    ## $("$($scriptName)</br>      </br>Computer:$env:computername </br>User:$env:username </br>PSver:"+($PSVersionTable.PSVersion.Major))
    ## </br> 
    ## $("     </br>IP: $($ipinfo.ip)</br>$($ipinfo.hostname)</br>$($ipinfo.org)</br>$($ipinfo.city)</br>$($ipinfo.region)</br>Coordinates=$($ipinfo.loc)")
    ## </br> </br>
    ## $("     Date: $(get-date -format "yyyy-MM-dd HH:mm:ss")")
    ## </br> </code>
    ## "
    ## ##
    ## WriteText "Sending to $($Globals.email_to)"
    ## $smtp.Send($msg)
    ## ########
	
	
    ## Globals Init with defaults                                            
    $AllCreds = @{}

    ## Globals Load from XML                                                 
    $AllCreds=GlobalsLoad $AllCreds $credentialXML $false	
    #if ($passes.Count -eq 1)     {        $admin_creds = $passes[0]    }
    #else     {        ### pick one        $admin_creds = $passes[0]    }
    ##
    $keyname = "$(${env:COMPUTERNAME})|$(${env:USERNAME})|$($service)|$($logon)"
    $pass_secstringastext = $AllCreds[$keyname]

    if (-not $set)
    {
        Try
        {
            ### ConvertTo-SecureString: SecureString_Plaintext >> SecureString (PSCreds use SecureString, XML stores SecureString_Plaintext)
            ##
            $encrypted = $pass_secstringastext | ConvertTo-SecureString  -ErrorAction Stop
            $credential = New-Object System.Management.Automation.PsCredential($logon, $encrypted) -ErrorAction Stop
            ##
            $return = $credential.GetNetworkCredential().password
            # -------------------------------------------------------
            # Create creds based on saved password using DPAPI.  
            # DPAPI is Microsoft's data protection method to store passwords at rest.  The files are only decryptable on the machine / user that created them.
            # 
            # Decrypt methods below are OK for debugging, as long as the decrypted values aren't saved
            #
            # Decrypt method 1
            # [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($pass_secstr_plaintext))
            #
            # Decrypt method 2
            # $PSCred.GetNetworkCredential().password
            # -------------------------------------------------------
        }
        Catch
        {
            Write-Warning "[Invalid or no password value for [$($keyname)]. Use 'Set-CredentialInFile' and try again."
            $return=$null
        }
        ## Globals Persist to XML
        if ($AllCreds["$($keyname)|Date_LastUsed"])
        {
            $AllCreds.Remove("$($keyname)|Date_LastUsed")
        }
        $AllCreds.Add("$($keyname)|Date_LastUsed",(Get-Date).ToString("yyyy-MM-dd hh:mm:ss"))
        GlobalsSave $AllCreds $credentialXML
    }

    if ($set)
    {
        # Save Cred to file
        if ($password)
        {
            $credential = Get-Credential -Message "Enter Password.  Press CANCEL to keep $("*" * $password.length)" -UserName $logon 
        }
        else
        {
            $credential = Get-Credential -Message "Enter Password" -UserName $logon 
        }
        
        if (-not $credential)
        {
            if ($password) 
            {
                $encrypted = ConvertTo-SecureString $password -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PsCredential($logon, $encrypted)
            }
        }
        if ($credential)
        {
            $pass_secstringastext = $credential.Password | ConvertFrom-SecureString ### saveable
            if ($AllCreds[$keyname])
                {
                    $AllCreds.Remove($keyname)
                }
            $AllCreds.Add($keyname,$pass_secstringastext)
            ###
            if ($AllCreds["$($keyname)|Date_Created"])
                {
                    $AllCreds.Remove("$($keyname)|Date_Created")
                }
            $AllCreds.Add("$($keyname)|Date_Created",(Get-Date).ToString("yyyy-MM-dd hh:mm:ss"))
            GlobalsSave $AllCreds $credentialXML
            #
            $return = $credential.GetNetworkCredential().password
        }
        else
        {
            $return = ""
        }
    }
    $return
}

Function Set-CredentialInFile
{
    Param (
         [string] $credentialXML
        ,[String] $service ="smtp"
		,[String] $logon ="logon"
        ,[String] $password =""
    )
	$return = Get-CredentialInFile $credentialXML $service $logon $true $password
    $return
}


Function VarExists
{
    Param ([String] $variable)
    if (Get-variable -Name $variable -ErrorAction SilentlyContinue)
    {
	    $true
    }
    else
    {
	    $false
    }
}

Function AskForChoice {
    ### Presents a list of choices to user
    ### if ((AskForChoice) -eq 0) {Write-Host "Aborting";Start-Sleep -Seconds 3; exit}
    ### $x=AskForChoice -message "All Done" -choices @("[D]one") -defaultChoice 0
    Param( $message="Continue?", $choices=@("&No","&Yes"), $defaultChoice=1)
    $choices = [System.Management.Automation.Host.ChoiceDescription[]] $choices
    $choice = $host.ui.PromptForChoice("",$message, $choices,$defaultChoice)
    $choice
    ###
}

Function ArrayRemoveDupes {
    ### Removes Dupes from an array of strings, without sorting the array
    Param( $str_arr=@("string3","string1","string2","string3","string2"))
    
    $return = @()
    ForEach ($str in $str_arr)
    {
    if (-not ($return.Contains($str)))
        {
        $return+=$str
        }
    }
    $return
}

Function Import-Vault
{
    
    ##################
    # Usage:
    # load vault values
    # $vault_folder = Join-Path (Split-Path -Path $scriptDir -Parent) "PowershellVault" # Vault folder is '..\PowershellVault'
    #
    # Create a blank unencrypted file
    # $vault = Import-Vault $vault_folder -encrypted $false
    #
    # Export the Encrypted file (this is a safe file to save - it can only be opened on the computer and by the user that created it, using DAPI)
    # Export-Vault $vault $vault_folder -encrypted $true
    #
    # Import the encyrpted file (it is unencrypted in memory)
    # $vault = Import-Vault $vault_folder -encrypted $true
    #
    # Export the encrypted file (Warning: delete this file when you are done - it contains plaintext passwords)
    # Export-Vault $vault $vault_folder -encrypted $false
    #
    # Used in a program
    #$vault_folder = Join-Path (Split-Path -Path $scriptDir -Parent) "PowershellVault" # Vault folder is '..\PowershellVault'
    #$vault = Import-Vault $vault_folder -encrypted $true
    #
    # To edit the vault
    #$vault_folder = Join-Path (Split-Path -Path $scriptDir -Parent) "PowershellVault" # Vault folder is '..\PowershellVault'
    #$vault = Import-Vault $vault_folder -encrypted $true
    #Export-Vault $vault $vault_folder -encrypted $false
    ###################################################
    ##### Pause here and edit the unencrypted file in the vault folder (Plaintext.csv)
    ##### Also, you can add any columns you like, but the column called SecureString will always get encrypted
    ###################################################
    #$vault = Import-Vault $vault_folder -encrypted $false
    #Export-Vault $vault $vault_folder -encrypted $true
    ###################################################
    
    
    ### Loads a powershell vault array of names values
    # if Vault file not found, one is created
    Param (
         [string]  $vault_folder="C:\VaultFiles"
        ,[boolean] $Encrypted=$true
        ,[string]  $Vault_name = "" # O365 or similar to prepend the vault file with
    )
    if (-Not (Test-Path -Path $vault_folder -PathType Container))
    {
        Throw "Couldn't find vault folder '$($vault_folder)'"
    }
    ##########
    if ($Vault_name -eq "")
    {
        $vault_filepre = "Vault_"
    }
    else
    {
        $vault_filepre = "Vault_$($Vault_name)_"
    }
    if ($encrypted)
    {
        $vault_filepost =""
    }
    else
    {
        $vault_filepost ="_PLAINTEXT"
    }
    $vault_file = "$($vault_folder)\$($vault_filepre)$($env:computername)_$($env:username)$($vault_filepost).csv"
    ############
    if (-Not (Test-Path -Path $vault_file -PathType Leaf))
    { #no vault file
        #Throw "Couldn't find vault file '$($vault_file)'"
        #
        #Encrypt using DAPI
        #$secstr_text = "P@ssword1" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
        #
        #Decrypt using DAPI
        #$str         = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($secstr))
        #
        if ($encrypted)
            { #if encrypted
            $secstr_text = "TestPassword" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
            } #if encrypted
        else
            { #not encrypted
            $secstr_text = "TestPassword"
            } #not encrypted
        $vault = [PSCustomObject]@{
            Name        = "TestName"
            SecureString= $secstr_text
            Description = "TestDescription"
            }
        Write-Warning "Couldn't find vault file '$($vault_file)', creating a template file."
        $vault | Export-Csv -Path $vault_file -Encoding ASCII -NoTypeInformation
        # Flip it back to plaintext
        $vault[0].SecureString = "TestPasssword"
    } #no vault file
    else
    { #found vault file
        $vault  = Import-Csv -Path $vault_file
        if ($encrypted)
        { #if encrypted
            # Decrypt vault
            ForEach ($v in $vault)
            {
                #$Decrypted= [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($v.SecureString))
                $Decrypted = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString $v.SecureString) ))
                $v.SecureString = $Decrypted
            }
        } #if encrypted
    } #found vault file
    # Return vault
    Return $vault
}

Function Export-Vault
{
    ### Saves a powershell vault array of names values
    Param (
        $vault
        ,[string]  $vault_folder="C:\VaultFiles"
        ,[boolean] $Encrypted=$true
        ,[string]  $Vault_name = ""   # O365 or similar to prepend the vault file with
    )
    if (-Not(Test-Path -Path $vault_folder -PathType Container))
    {
        Throw "Couldn't find vault folder '$($vault_folder)'"
    }
    ##########
    if ($Vault_name -eq "")
    {
        $vault_filepre = "Vault_"
    }
    else
    {
        $vault_filepre = "Vault_$($Vault_name)_"
    }
    if ($encrypted)
    {
        $vault_filepost =""
    }
    else
    {
        $vault_filepost ="_PLAINTEXT"
    }
    $vault_file = "$($vault_folder)\$($vault_filepre)$($env:computername)_$($env:username)$($vault_filepost).csv"
    ############
    
    if ($encrypted)
    { #if encrypted
        # copy vault
        $vault2 = $vault | Select *
        # Encrypt vault
        ForEach ($v in $vault2)
        {
            if ($v.SecureString  -ne "")
            {
                $secstr_text = $v.SecureString | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
                $v.SecureString = $secstr_text
            }
        }
        $vault2 | Export-Csv -Path $vault_file -Encoding ascii -NoTypeInformation
    } #if encrypted
    else
    { #not encrypted
        $vault | Export-Csv -Path $vault_file -Encoding ascii -NoTypeInformation
    } #not encrypted
   
    Return $null
}