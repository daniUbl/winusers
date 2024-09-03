#===========================================================================
# OCS Inventory Reports - For Versions: Windows Server 2008, 2012 R2 and 2016
# Plugin WinUsers 
# version 1.0.1 - 03/09/2024
#
# modify by Umbler.com
#===========================================================================

# Function to get Admin user status
function Get-AdminUser {
	param([string] $username)

	$admingroup = ""
	try {
		$admingroup = net localgroup Administrators
	} catch {
   	$admingroup = Get-WmiObject -Class Win32_Group -Filter "Name='Administrators'" | ForEach-Object { $_.GetRelated('Win32_UserAccount') } | Select-Object -ExpandProperty Name
	}

	$userType = "Local"

	foreach ($member in $admingroup) {
		if ($member.Trim() -eq $username) {
			$userType = "Admin"
			break
		}
	}

	return $userType
}


# Function to get user folder size
function Get-Size
{
	param([string]$pth)
	try {
		"{0:n2}" -f ((gci -path $pth -recurse -ErrorAction Ignore | measure-object -ErrorAction Stop -property length -sum).sum /1mb)
	} catch {
		"{0:n2}" -f 0
	}
}


# Check if user belongs to group do IIS (IIS_IUSRS)
function Check-User-IIS {
	param([string] $username)

	$iisgroup = ""
	try {
		$iisgroup = net localgroup IIS_IUSRS
	} catch {
		$iisgroup = Get-WmiObject -Class Win32_Group -Filter "Name='IIS_IUSRS'" | ForEach-Object { $_.GetRelated('Win32_UserAccount') } | Select-Object -ExpandProperty Name
	}

	$descriptionCheck = ""

	foreach ($member in $iisgroup){
		if ($member.Trim() -eq $username) {
            $descriptionCheck = "`n`n[* Usuario Membro do Grupo: IIS_IUSRS *]"
            break
        }
	}

	return $descriptionCheck
}


# Check if user belongs to group do "Remote Desktop Users"
function Check-User-Remote {
	param([string] $username)

	$remotegroup = ""
	try {
		$remotegroup = net localgroup "Remote Desktop Users"
	} catch {
		$remotegroup = Get-WmiObject -Class Win32_Group -Filter "Name='Remote Desktop Users'" | ForEach-Object { $_.GetRelated('Win32_UserAccount') } | Select-Object -ExpandProperty Name
	}

	$descriptionCheck = ""

	foreach ($member in $remotegroup){
		if ($member.Trim() -eq $username) {
            $descriptionCheck = "`n`n[* Usuario Membro do Grupo: Remote Desktop Users *]"
            break
        }
	}

	return $descriptionCheck
}

#################################
#          Local User           #
#################################
$users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Select *
$pathUsers = "C:\Users"
$allUsers = @()

$startTime = (get-date).AddDays(-15)
$logEvents = Get-Eventlog -LogName Security -After $startTime | where {$_.eventID -eq 4624}

foreach ($user in $users) {
	if($user.Name -ne $null){
        $userDaVez = $user.Name


        $userType = Get-AdminUser $user.Name
        $path = "C:\Users\"+ $user.Name
		$folderSize = Get-Size $path

        if($user.Disabled) { $userStatus = "Disabled" } else { $userStatus = "Enabled" }

        $numberConnexion = 0
		$workstation = ""
		$numberRemoteConnexion = 0
		$ipRemote ="" 

        foreach($userconnection in $logEvents){
            #In local logon
			if(($userconnection.ReplacementStrings[5] -eq $user.Name) -and (($userconnection.ReplacementStrings[8] -eq 2) -or ($userconnection.ReplacementStrings[8] -eq 7))){
				$numberConnexion = $numberConnexion + 1
				$workstation = $userconnection.ReplacementStrings[11]
			#In remote
			}if (($userconnection.ReplacementStrings[5] -eq $user.Name ) -and ($userconnection.ReplacementStrings[8] -eq 10)){
				$workstation = $userconnection.ReplacementStrings[11]
				$numberRemoteConnexion = $numberRemoteConnexion + 1
				$ipRemote = $userconnection.ReplacementStrings[18]
			}
        }

        # verificar se o usuário está no grupo do IIS:
		$descriptionUser = Check-User-IIS $user.Name
		$user.Description += $descriptionUser

		# verificar se usuário está no grupo do "Remote Desktop Users"
		$descriptionUser = Check-User-Remote $user.Name
		$user.Description += $descriptionUser

        
		$xml += "<WINUSERS>`n"
		$xml += "<NAME>"+ $user.Name +"</NAME>`n"
		$xml += "<TYPE>"+ $userType +"</TYPE>`n"
		$xml += "<SIZE>"+ $folderSize +"</SIZE>`n"
		$xml += "<LASTLOGON>"+ $user.LastLogon +"</LASTLOGON>`n"
		$xml += "<DESCRIPTION>"+ $user.Description +"</DESCRIPTION>`n"
		$xml += "<STATUS>"+ $userStatus +"</STATUS>`n"
		$xml += "<USERMAYCHANGEPWD>"+ $user.UserMayChangePassword +"</USERMAYCHANGEPWD>`n"
		$xml += "<PASSWORDEXPIRES>"+ $user.PasswordExpires +"</PASSWORDEXPIRES>`n"
		$xml += "<SID>"+ $user.SID +"</SID>`n"
		$xml += "<USERCONNECTION>"+ $numberConnexion +"</USERCONNECTION>`n"
		$xml += "<NUMBERREMOTECONNECTION>"+ $numberRemoteConnexion +"</NUMBERREMOTECONNECTION>`n"
		$xml += "<IPREMOTE>"+ $ipRemote +"</IPREMOTE>`n"
		$xml += "</WINUSERS>`n"

		$allUsers += $user.Name
    }
}


try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
[Console]::WriteLine($xml)
