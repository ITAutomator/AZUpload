Overview
This .ps1 will assist with importing local PST data into Office365 mailboxes
 
It works by bulk uploading PST files into a free ingestion folder provided by AzureAD<br>
Then a CSV file instructs Office365 as to which PST files go into which mailbox (or mailbox archive)<br>
These ingestion folder self-destructs 30 days (after the last file upload)
 
Basically, this guide is based on this guide from Microsoft: PST Import <br>
[Microsoft Guide](https://learn.microsoft.com/en-us/microsoft-365/compliance/use-network-upload-to-import-pst-files?redirectSourcePath=%252fen-us%252farticle%252fUse-network-upload-to-import-your-organization-s-PST-files-to-Office-365-103f940c-0468-4e1a-b527-cc8ad13a5ea6&view=o365-worldwide#step1) 
see also [SymmetrixTech guide](https://symmetrixtech.com/bulk-office-365-mail-imports/) <br>
However, using this script you can avoid all the command line stuff

![AZUPload1](https://github.com/ITAutomator/AZUpload/assets/135157036/809a2fb1-8686-4fcc-971e-d8dbfb90b57a)


## Step by Step

1.	Give yourself the Import Role (You only do this once per O365 Org)<br>
_Admin Centers > Exchange Admin Center > Permissions (left) > admin roles (top) > Organization Management > Edit > Add Role: Mailbox Import Export_<br>
(May take 24 hours)


2.	Setup the AZUpload program (On a computer with disk space and fast upload)<br>
Download AZCopy.exe tool from here: https://aka.ms/downloadazcopy and install<br>
Download Azure Storage Explorer (optional)<br>
https://azure.microsoft.com/en-us/features/storage-explorer <br>
Copy this program folder AZUpload to __C:\AZUpload__ (or D:, there is no setup program)<br>

AZUpload.ps1 (right-click) > Run <br>
Run through the program once, just clicking OK on the defaults, to create the folder structure it uses.


3.	Copy the PST files into 1-Stage subfolder
Put each person’s PST files in folders according to their email address (without the @domain)<br>
This way the program knowns which files go to which mailbox.

C:\AZUpload\1-Stage\<username>

_C:\AZUpload\1-Stage\jsmith\pstfile1.pst<br>
C:\AZUpload\1-Stage\jsmith\pstfile2.pst<br>
C:\AZUpload\1-Stage\tjohnson\pstfile1.pst<br>
C:\AZUpload\1-Stage\tjohnson\pstfile2.pst_<br>


4.	Understand people’s mailbox sizes and archive ON/OFF status<br>
_Note: The user must already have an archive mailbox<br>
See ‘How to turn on Archive Mailbox’ below_


5.	Create an O365 Import job<br>
_Admin Centers > Security & Compliance Center (Office 365 compliance center)_<br>
https://compliance.microsoft.com/homepage<br>
https://protection.office.com/import<br>
_Data governance/Information governance(left) > Import (top) > click 'New import job' button_<br>
Note: If you don't see 'New import job' then you have to add the role (or wait 24 hours)<br>
 
Job Name: _jsmith202101_  (or whatever, all lowercase, no hyphens, no spaces)<br>
Job Method: _upload your data_


6.	Show SAS URL/URI: Click the link 'show network upload SAS URL' and keep it for later<br>
(Skip this step if you are doing a 2nd or 3rd pass of uploads, you don't need another SAS URL)
 
 
7.	Run the AZUpload.ps1

Give it your email domain<br>
Give it the SAS URL (from your import job above)
 
It will move the files through 3 folders (it will make 2 and 3 if needed)
 
1-Stage`\<username>\`.pst files <br>
  This is where the .pst files start out  <br>
  Create a folder for each user and dump their PST files in the folder <br>
  `<username>` must match the email address without the domain name  <br>
  Stuff in here will be renamed according to username and moved to queue folder<br>
   
2-Queue<br>
  Anything in this folder will get pushed as-is to O365 <br>
  It is important to avoid name collisions since O365 ingestion folder is flat  <br>
  Normally this folder is populated from 1-Stage but you can manually put files in here.  <br>
  As long as you follow the "`<username>` pstname.pst" format  <br>
  (since the first word is used to create the .csv mapping file)
  
3-Sent  <br>
  After successful send to O365 files are finally moved here <br>


Between Queue and Sent it will launch AZCopy.exe (minimized) and show progress<br>
It's moving even though may say the word finished (fyi 11 MB/s is about 40G / hour)

_Note: If you click inside the minimized AZCopy black screen (cmdline screen) and it seems to freeze it may be paused.  Press spacebar to unpause.  This is standard DOS program behavior._
 
Azure Storage Explorer (optional)<br>
Run Azure Storage Explorer to see the files in temp cloud

(first time) Storage Accounts (right-click) > Connect to Azure Storage<br>
--> Use a shared access signature (SAS) URI<br>
_Display name: (job name from above)_<br>
_URI: (SAS URI from above)_<br>

  
8.	AZUpload.ps1 will continue uploading in the background.

Mapping files and log files are in the root.<br>
When it finishes it will say Done, but you should be able to continue with the remaining steps while it uploads.

  
9.	Fix up the CSV - main mailbox or archive mailbox

FALSE meaning ‘main mailbox’  <br>
__TRUE if you want to put files in the ‘archive mailbox’ (default)__  <br>
Note: The user must already have an archive mailbox  <br>
See ‘How to turn on Archive Mailbox’ below <br>

The last column has a ‘/’ meaning root folder (mixed in with the existing mail) or you could put something like ‘/ImportedPst’ and it will create a subfolder
 
>Name,Mailbox,IsArchive,TargetRootFolder  
jsmith JS 2008.pst,jsmith@cscapitaladvisors.com,FALSE,/  
jsmith JS 2013 Part1.pst,jsmith@cscapitaladvisors.com,FALSE,/  
jsmith JS Archive.2013.pst,jsmith@cscapitaladvisors.com,FALSE,/
  
 
10.	Upload CSV to Microsoft<br>
  Back on the web page for your job:  <br>
_Tick 'I'm done uploading'_  <br>
_Tick 'I have access to the mapping file'_  <br>
Upload your CSV  <br>
_Click 'Validate'_  <br>
Your file will be validated and analyzed.  (may take a minute for it to register in the cloud, keep trying)<br>
  
_Click 'Save'_
 
  
11.	Import from AZcloud to mailbox (this is all in the cloud)  <br>
You should get an Email confirming it's done.    <br>
Or just refresh the web page until it says _Status=Analysis completed_
  
Open the job and Click _(Ready to) Import to Office 365_ and import it  <br>
Click 'No I want to import everything' (it will detect that it’s old data and warn you)  <br>
Go ahead and Import<br>
  

12.	Wait for import to finish  <br>
You can monitor progress on the web page until it is finished.  <br>
You will get an email when it is finished too.<br>
  

13.	Retention policies – turn off retention hold (_Optional but eventually should be done_)

a.	Overview<br>  
The import process suspends Retention policies (Sets RetentionHold Enabled = $true) 
for the user.  The policy, normally / when unheld, moves older mail automatically to the archive (if there is one).<br>
The hold is put in place so that data impored doesn’t get again moved by the retention polices, which would be confusing (e.g. import to main mailbox, but its old, so the policy moves it to the archive).

When it’s done, turn off, the hold:<br>  
There’s no way to do this in the EAC, you must use powershell.

b.	Turn OFF retention holds<br>  
Go ahead and paste (one by one), the uncommented lines into the BLUE command line area and press enter after each

```## Retention Hold  <br>
## show all mailboxes that have it ON  
Get-Mailbox * | Where-Object RetentionHoldEnabled -EQ $True| Select Name, RetentionHoldEnabled  
## turn it OFF for those that have it ON  
Get-Mailbox * | Where-Object RetentionHoldEnabled -EQ $True| Set-Mailbox -RetentionHoldEnabled $false 
```


14.	You are done!  <br>
The user should now see (automatically) an archive mailbox underneath their normal mailbox (In both Outlook and Outlook for Web).

__Appendix__

__How to turn on Archive Mailbox__ <br>
_Note: The user must already have an archive mailbox  <br>
(old) Exchange admin center > Recips > Mailboxes  > Mailbox Features (left) > Archiving > Enable   <br>
(new) EAC > Mailboxes > User > Manage mailbox archive > ON_<br>

  
By default, people’s archive mailbox is OFF.  If they are near their main mailbox threshold, archiving should probably be turned ON.   <br>
_If you the user doesn’t have an archive mailbox, CSV rows that target the archive will fail._<br>

To turn on the Archive mailbox for a user (turn on In-Place Archive)<br>  
_EAC > Mailboxes > User > Edit (Pencil on top) > Mailbox Features (left) > Archiving > Enable_
  
Note: If Enabled – this area shows Archive size plus option to Disable (which permanently deletes the mail in Archive)  

[What are the storage limits for mailboxes / archive mailboxes?](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits#storage-limits)

__Using Azure Storage Explorer__

This is a free tool to browse your temp storage area in the cloud <br> 
[Azure Storage Explorer – cloud storage management | Microsoft Azure](https://azure.microsoft.com/en-us/products/storage/storage-explorer/)

To update: Just click the menu item to Check for Update

To see storage: Press the connect (plug icon) on the left<br>
Connect to Azure Storage: Use a shared access signature (SAS) URI  
Paste in your URI

To import files that were uploaded into AZExplorer storage

You will notice using the Azure Storage Explorer that successive uploads all go to the same ‘Ingestion Data’ area for the Org. Even though the SAS URI values vary.

Knowing this, you can create a CSV file and import job based on the PST files already in storage:<br>
a.	Go to the page showing the Import PST files job lists and click ‘Download list of PST Files’<br>
b.	Open that list and paste the filenames into a new CSV based on an earlier upload.  <br>
c.	Then start a new import job and skip right to the upload CSV file, it should validate<br>
![Picture1](https://github.com/ITAutomator/AZUpload/assets/135157036/675afaf6-f2a6-43b8-a03c-95c0d9b3b9ed)


