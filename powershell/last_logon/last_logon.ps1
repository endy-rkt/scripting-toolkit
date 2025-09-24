#who is the last user who logs on?
$outFile = "user_list.csv"
$userList = Get-LocalUser | Select-Object Name, LastLogon

$userList | Export-Csv -Path $outFile -NoTypeInFormation


$lastLogonUser = Get-LocalUser | Sort-Object LastLogon -Descending | Select-Object -First 1 Name, LastLogon | Out-String
Write-Host $lastLogonUser