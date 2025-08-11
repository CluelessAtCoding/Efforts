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
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'" + " " + $filetobeunblocked
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
       
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess) 
 
       #Exit from the current, unelevated, process
       Exit
        
    }
}

$filetobeunblocked=$args

#Check Script is running with Elevated Privileges
Check-RunAsAdministrator

Write-Host "The file path that will be unblocked is $filetobeunblocked"

$matchingapprules = Get-NetFirewallApplicationFilter -Program "$($filetobeunblocked)" | Get-NetFirewallRule
$wantedrules = $matchingapprules | Where-Object Description -eq "Custom Rule created from context menu"

$x=0
foreach ($rule in $wantedrules){
    $DisplayName = $rule.DisplayName
    Write-Host "Removing Rule $DisplayName"
    Remove-NetFirewallRule $rule.Name
    $x++
}

Write-Host "$($x) rule(s) removed. "
start-sleep -seconds 5