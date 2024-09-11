# FolderBackup
PowerShell script that takes a copy of a given directory and saves it in another location.<br>
The script will save ALL backups made within the last 7 days. To save space and disk writes, backups will be skipped if folder hash matches previous backup.<br>
Outside of this, the script will cleanup old backups except:<br>
- The last backup of every day (for the last 30 days)
- The last backup of every month

# Usage
Requires parameters to run:
 - "-PathToBackup <Filepath>" - Required to run. This specifies what directory you want to backup
 - "-PathToSaveBackup <Filepath>" - Optional. Path where backups should be stored. If not specified, the parent directory of the PathToBackup will be used instead.
 - "-Zip" - Optional. Instead of copy/pasting the directory, script will create a .zip file instead.
 - "-NoLogging" - Optional. Disables writing to log file.

As an example, using task scheduler you can setup an hourly action to use the following program and arguments:<br>
**Program:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe<br>
**Arguments:** -File "C:\PathToTheScript\FolderBackup.ps1" -PathToBackup "C:\ExamplePath\ToMyProject" -PathToSaveBackup "C:\Users\EXAMPLE\OneDrive\Documents\MyProjectBackups" -Zip<br>

# Recommendations
- Recommend using with Task Scheduler on an hourly basis.
- Recommend storing the destination files in a cloud sync'd location (eg OneDrive, Sync.com, Dropbox etc etc).
