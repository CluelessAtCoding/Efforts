Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'" + " " + $filetobeblocked
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
       
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess) 
 
       #Exit from the current, unelevated, process
       Exit
        
    }
}

$filetobeblocked=$args[0]

#Check Script is running with Elevated Privileges
Check-RunAsAdministrator

Write-Host "The file path that will be blocked is $filetobeblocked"
$filename = $filetobeblocked.split("\")[-1]

New-NetFirewallRule -DisplayName "Custom Outbound File Block - $filename" -Description "Custom Rule created from context menu" -Direction Outbound -Program $filetobeblocked -Action Block
start-sleep -seconds 2