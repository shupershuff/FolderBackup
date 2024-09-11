<#
Name: FolderBackup
Author: Shupershuff
Usage: Creates zips of a folder
Version: 1.0
Notes: Run this with Task Scheduler
#>

param(
	[String]$PathToBackup,[String]$PathToSaveBackup,[Switch]$NoLogging,[switch]$zip,[switch]$debug
)
if ($debug -eq $True){#courtesy of https://thesurlyadmin.com/2015/10/20/transcript-logging-why-you-should-do-it/
	$KeepLogsFor = 15
	$VerbosePreference = "Continue"
	$LogPath = Split-Path $MyInvocation.MyCommand.Path
	Get-ChildItem "$LogPath\*.log" | Where LastWriteTime -LT (Get-Date).AddDays(-$KeepLogsFor) | Remove-Item -Confirm:$false
	$LogPathName = Join-Path -Path $LogPath -ChildPath "$($MyInvocation.MyCommand.Name)-$(Get-Date -Format 'MM-dd-yyyy').debug.log"
	Start-Transcript $LogPathName -Append
}
$ScriptFileName = Split-Path $MyInvocation.MyCommand.Path -Leaf
$WorkingDirectory = ((Get-ChildItem -Path $PSScriptRoot)[0].fullname).substring(0,((Get-ChildItem -Path $PSScriptRoot)[0].fullname).lastindexof('\')) #Set Current Directory path.
##########################################################################################################
# Startup Bits
##########################################################################################################
$LogsToKeep = 7

##########################################################################################################
# Script Functions
##########################################################################################################

Function Green {#Used for outputting green scucess text
    process { Write-Host $_ -ForegroundColor Green }
}
Function Yellow {#Used for outputting yellow warning text
    process { Write-Host $_ -ForegroundColor Yellow }
}
Function Red {#Used for outputting red error text
    process { Write-Host $_ -ForegroundColor Red }
}
Function WriteLog {
	#Determine what kind of text is being written and output to log and console.
	#Note: $NoLogging is a script parameter and if true will not output to standard log file. If CustomLogFile param is used, output will continue to be written.
	Param ( [string]$LogString,
			[switch]$Info, #Standard messages.
			[switch]$Verbose, #Only enters into log if $VerbosePreference is set to continue (Default is silentlycontinue). For Debug purposes only.
			[switch]$Errorlog, #Can't use $Error as this is a built in PowerShell variable to recall last error. #Red coloured output text in console and sets log message type to [ERROR]
			[switch]$Warning, #Cheese coloured output text in console and sets log message type to [WARNING]
			[switch]$Success, #Green output text in console and sets log message type to [SUCCESS]
			[switch]$NewLine, #used to enter in additional lines without redundantly entering in datetime and message type. Useful for longer messages.
			[switch]$NoNewLine, #used to enter in text without creating another line. Useful for text you want added succinctly to log but not outputted to console
			[switch]$NoConsole, #Write to log but not to Console
			[string]$CustomLogFile #Explicitly specify the output filename.
	)
	if ($CustomLogFile -eq ""){	
		$Script:LogFile = ($WorkingDirectory + "\" + $ScriptFileName.replace(".ps1","_")  + (("{0:yyyy/MM/dd}" -f (get-date)) -replace "/",".") + "_log.txt")
	}
	Else {
		$Script:LogFile = ($WorkingDirectory + "\" + $CustomLogFile)
	} 
	if ((Test-Path $LogFile) -ne $true){
		Add-content $LogFile -value "" #Create empty Logfile
	}
	if (!(($Info,$Verbose,$Errorlog,$Warning,$Success) -eq $True)) {
		$Info = $True #If no parameter has been specified, Set the Default log entry to type: Info
	}
    $DateTime = "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)
	If ($CheckedLogFile -ne $True){
		$fileContent = Get-Content -Path $Script:LogFile
		if  ($Null -ne $fileContent){
			if ($fileContent[2] -match '\[(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]') {#look at 3rd line of log file and match the date patern.
				$firstDate = [datetime]::ParseExact($matches[1], 'dd/MM/yy HH:mm:ss', $null) #convert matched date string to variable
				$IsTodaysLogFile = ($firstDate.Date -eq (Get-Date).Date) #compare match against todays date
			}
			if ($IsTodaysLogFile -eq $False){
				Rename-Item $Script:LogFile ($WorkingDirectory + "\" + $ScriptFileName.replace(".ps1","_") + (("{0:yyyy/MM/dd}" -f $firstDate) -replace "/",".") + "_log.txt")
				Write-Verbose "Archived Log file."
			}
			#Check if there's more than 3 logfiles with a date and if so delete the oldest one
			$logFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*.txt" | Where-Object { $_.Name -match '\d{2}\.\d{2}\.\d{2}_?\S*log\.txt' }
			$logFilesToKeep = $logFiles | Sort-Object name -Descending | Select-Object -First $LogsToKeep #sorting by Name rather than LastWriteTime in case someone looks back and edits it.
			$logFilesToDelete = $logFiles | Where-Object { $_ -notin $logFilesToKeep }
			foreach ($fileToDelete in $logFilesToDelete) {# Delete log files that exceed the latest $LogsToKeep
				Remove-Item -Path $fileToDelete.FullName -Force
				Write-Verbose ("Deleted " + $fileToDelete.FullName)
			}
		}
		$Script:CheckedLogFile = $True
	}
	if ($True -eq $Info) {
		$LogMessage = "$Datetime [INFO]    - $LogString"
		if ($False -eq $NoConsole){
			write-output $LogString
		}
	}
	if ($True -eq $Verbose) {
		if ($VerbosePreference -eq "Continue") {
			$LogMessage = "$Datetime [VERBOSE] - $LogString"
			if ($False -eq $NoConsole){
				write-output $LogString
			}
		}
	}
	if ($True -eq $Errorlog) {
		$LogMessage = "$Datetime [ERROR]   - $LogString"
		if ($False -eq $NoConsole){
			write-output $LogString | Red
		}
	}
	if ($True -eq $Warning) {
		$LogMessage = "$Datetime [WARNING] - $LogString"
		if ($False -eq $NoConsole){
			write-output $LogString | Yellow
		}
	}
	if ($True -eq $Success) {
		$LogMessage = "$Datetime [SUCCESS] - $LogString"
		if ($False -eq $NoConsole){
			write-output $LogString | Green
		}
	}
	if ($True -eq $NewLine){#Overwrite $LogMessage to remove headers if -newline is enabled
		$LogMessage = "                                $LogString"
	}
	if (($NoLogging -eq $False -or ($CustomLogFile -ne "" -and $LogPlayers -eq $True)) -and $NoNewLine -eq $True ){#Overwrite $LogMessage to put text immediately after last line if -nonewline is enabled
		$LogContent = (Get-Content -Path $LogFile -Raw) # Read the content of the file
		if ($logcontent -match ' \r?\n\r?\n$' -or $logcontent -match ' \r?\n$' -or $logcontent -match ' \r?\n$' -or $logcontent[-1] -eq " "){#if the last characters in the file is a space a space with one or two line breaks
			$Space = " "
		}
		$LogContent = $LogContent.trim()
		$words = $LogContent -split '\s+' # Split the content into words
		$lastWord = $words[-1] # Get the last word
		$lastWordPosition = $LogContent.LastIndexOf($lastWord) # Find the last occurrence of the last word in the content
		$LogMessage = $lastWord + $Space + $LogString #"$lastLine$LogString"
		$newContent = $LogContent.Substring(0, $lastWordPosition) + $LogMessage + $LogContent.Substring($lastWordPosition + $lastWord.Length) # Replace the last occurrence of the last word in the content
		$newContent | Set-Content -Path $LogFile # Write the modified content back to the file
	}
	while ($Complete -ne $True -and $WriteAttempts -ne 3){
		try {
			if (($NoLogging -eq $False -or ($CustomLogFile -ne "" -and $LogPlayers -eq $True)) -and $NoNewLine -eq $False ){ #if user has disabled logging, eg on sensors that check every minute or so, they may want logging disabled.
				Add-content $LogFile -value $LogMessage -ErrorAction Stop
				$Complete = $True
			}
			else {
				write-verbose "No Logging specified, didn't write to log."
				$Complete = $True
			}
		}
		Catch {#added this in case log file is being written to too fast and file is still locked when trying from previous write when trying to write new line to it.
			write-verbose "Unable write to $LogFile. Check permissions on this folder"
			$WriteAttempts ++
			start-sleep -milliseconds 5
		}
	}
}
Function Backup {
	# Helper function to calculate a folder hash
	Function Get-FolderHash {
		param ([string]$folderPath)	
		# Get all files in the folder, sorted by name to ensure consistency
		$files = Get-ChildItem -Path $folderPath -Recurse | Sort-Object FullName
		# Initialize a string to combine file hashes
		$combinedHashes = ""
		# Calculate a hash for each file
		foreach ($file in $files) {
			if (-not $file.PSIsContainer) {
				$fileHash = Get-FileHash -Path $file.FullName -Algorithm SHA256
				$combinedHashes += $fileHash.Hash
			}
		}
		# Hash the combined string of file hashes
		$finalHash = [System.BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedHashes)))
		return $finalHash.Replace("-", "")
	}
	
	# Get the current date and time
	$currentDateTime = Get-Date
	# Format the date and time components
	$year = $currentDateTime.Year
	$month = $currentDateTime.ToString("MMMM")
	$day = $currentDateTime.ToString("dd")
	$hour = $currentDateTime.ToString("HHmm")

	# Check if there's a previous backup hash to compare
    $HashFilePath = Join-Path -Path $PathToSaveBackup -ChildPath "last_backup_hash.txt"
    $PreviousHash = if (Test-Path $HashFilePath) { Get-Content $HashFilePath } else { "" }

    # Calculate the current folder hash
    $CurrentHash = Get-FolderHash -folderPath $PathToBackup

    # Compare hashes and decide if a backup is needed
    if ($CurrentHash -eq $PreviousHash) {
        WriteLog -info "Backup: Folder has not changed since the last backup. No backup will be made."
        return
    }

	# Construct the destination path
	$destinationPath = Join-Path -Path $PathToSaveBackup -ChildPath "$year\$month\$day\$hour"
	# Create the destination directory if it doesn't exist
	if (-not (Test-Path $destinationPath)) {
		WriteLog -info "Backup: Creating Backup Folder in $PathToSaveBackup"
		New-Item -ItemType Directory -Path $destinationPath -Force | out-null
	}

	# Copy the folder to the destination or create a zip file
	if ($Zip) { # If the Zip switch is used, create a zip file instead of copying the folder
		$ZipFilePath = Join-Path -Path $PathToSaveBackup -ChildPath ("$year\$month\$day\$Hour\$Year." + $currentDateTime.ToString("MM") + ".$day-$hour.zip")
		WriteLog -info "Backup: Creating ZIP archive at $ZipFilePath"
		try {
			# Use Compress-Archive to zip the folder
			Compress-Archive -Path "$PathToBackup\*" -DestinationPath $ZipFilePath
			WriteLog -success "Backup: ZIP archive created at $ZipFilePath"
		}
		catch {
			WriteLog -error "Backup: Failed to create ZIP archive. $_"
		}
	} else {
		# Copy the folder to the destination if not zipping
		Copy-Item -Path $PathToBackup -Destination $destinationPath -Recurse -Force | Out-Null
		WriteLog -success "Backup: Save Data copied to: $destinationPath"
	}
	# Save the current folder hash for future comparisons
	$CurrentHash | Out-File -FilePath $HashFilePath -Force	
	
	#Start Cleanup Tasks
	Writelog -info -noconsole "Backup: "
	Writelog -info -nonewline "Checking for old backups that can be cleaned up..."
	$DirectoryArray = New-Object -TypeName System.Collections.ArrayList
	Get-ChildItem -Path "$PathToSaveBackup\" -Directory -recurse -Depth 3 | Where-Object {$_.FullName -match '\\\d{4}\\\w+\\\d+\\\d{4}$'} | ForEach-Object {
		$DirectoryObject = New-Object -TypeName PSObject
		$pathComponents = $_.FullName -split '\\'
		$year = $pathComponents[-4]
		$month = $pathComponents[-3]
		$month = [datetime]::ParseExact($month, 'MMMM', $null).Month # convert month from text to number. EG February to 02
		$day = $pathComponents[-2]
		$time = $pathComponents[-1]
		$hour = $time[0]+$time[1]
		$minute = $time[2]+$time[3]
		$dateInFolder = Get-Date -Year $year -Month $month -Day $day -Hour $hour -minute $minute -second 00 #$minute can be changed to 00 if we want all the folders to be nicely named.
		$ShortFolderDate = (Get-Date -Year $year -Month $month -Day $day).ToString("d")
		Add-Member -InputObject $DirectoryObject -MemberType NoteProperty -Name FullPath -Value $_.FullName
		Add-Member -InputObject $DirectoryObject -MemberType NoteProperty -Name FolderDate -Value $dateInFolder
		Add-Member -InputObject $DirectoryObject -MemberType NoteProperty -Name ShortDate -Value $ShortFolderDate
		[VOID]$DirectoryArray.Add($DirectoryObject)
	}
	$DirectoryArray = $DirectoryArray | Sort-Object {[datetime]$_.FolderDate} -Descending
	$HourliesToKeep = $DirectoryArray | Group-Object -Property ShortDate | Select-Object -First 7 | select -expandproperty group #hourlies. These aren't necessarily hourly, can be taken every few minutes if desired
	$DailiesToKeep = $DirectoryArray | Group-Object -Property ShortDate | ForEach-Object { $_.Group[0] } | Select-Object -skip 7 -First 24 #this is actually useful for capturing the last backup of each day
	$MonthliesToKeep = $DirectoryArray | Group-Object -Property { ($_.ShortDate -split '/')[1] } | ForEach-Object { $_.Group[0] }
	#Perform steps to remove any old backups that aren't needed anymore. Keep all backups within last 7 days (even if last 7 days aren't contiguous). For the last 30 days, keep only the last backup taken on that day (Note that again, 30 days aren't necessarily contiguous). For all older backups, only keep the last backup taken that month.
	foreach ($Folder in $DirectoryArray){
		if ($MonthliesToKeep.FullPath -notcontains $Folder.FullPath -and $DailiesToKeep.FullPath -notcontains $Folder.FullPath -and $HourliesToKeep.FullPath -notcontains $Folder.FullPath){
			$Folder | Add-Member -MemberType NoteProperty -Name KeepFolder -Value "Deleted"
			Remove-Item -Path $Folder.FullPath -Recurse -Force
			Writelog -warning -noconsole "Backup: "
			Writelog -warning -nonewline "Removed $($Folder.FullPath)"
			$Cleanup = $True
		}
		Else {
			$Folder | Add-Member -MemberType NoteProperty -Name KeepFolder -Value $True
		}
	}
	#Perform steps to Cleanup any empty directories.
	Function IsDirectoryEmpty($directory) { #Function to check each directory and subdirectory to determine if it's actually empty.
		$files = Get-ChildItem -Path $directory -File
		if ($files.Count -eq 0) { #directory has no files in it, checking subdirectories.
			$subdirectories = Get-ChildItem -Path $directory -Directory
			foreach ($subdirectory in $subdirectories) {
				if (-not (IsDirectoryEmpty $subdirectory.FullName)) {
					return $false #subdirectory has files in it
				}
			}
			return $true #directory is empty
		}
		return $false #directory has files in it.
	}
	$subdirectories = Get-ChildItem -Path $PathToSaveBackup -recurse -Directory
	foreach ($subdirectory in $subdirectories) {
		if (IsDirectoryEmpty $subdirectory.FullName) { # Check if the subdirectory is empty (no files)
			Remove-Item -Path $subdirectory.FullName -Force -Recurse # Remove the subdirectory
			Writelog -warning -noconsole "Backup: "
			Writelog -warning -nonewline "Deleted empty folder: $($subdirectory.FullName)"
			$Cleanup = $True
		}
	}
	Writelog -success -noconsole "Backup: "
	if ($Cleanup -eq $True){
		Writelog -success -nonewline "Backup cleanup complete."
	}
	Else {
		Writelog -success -nonewline "No cleanup required."
	}
}
Function ExitFunction {#Used to write to log prior to exit
	if ($ErrorOut -eq $True){
		WriteLog -errorlog "Errors prevented script from running. Please see log file." #if no save path specified in config
	}
	WriteLog -info -noconsole "Script Exited."
	Start-Sleep 4
	Exit
}
WriteLog -newline
if ($PathToBackup -eq ""){
	WriteLog -errorlog "Path to Folder to Backup wasn't specified." #if no backup path specified in config
	WriteLog -errorlog -newline "Please use parameter -PathToBackup `"<YourFilepathHere>`""
	$Script:ErrorOut = $True
	ExitFunction
}
if ($PathToSaveBackup -eq ""){
	$PathToSaveBackup = Split-Path -Path $PathToBackup -Parent
	WriteLog -warning "Path to where Backup should be saved wasn't specified." #if no save path specified in config
	WriteLog -warning -newline "Parent directory of the backup directory will be set as the destination path: `"$PathToSaveBackup`""
	WriteLog -warning -newline "If you would like to specify another destination path, please use parameter -PathToSaveBackup `"<YourFilepathHere>`""
}
Backup
