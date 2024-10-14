#===========================================================================
# Author: Danielly Brito
# Email: danielly.brito@umbler.com
# Plugin WinUsers 
# OCS Inventory Reports - For All Versions of Windows Servers
# Description: Busca por todos os usuários do sistema, verifica se é Administrator ou Local, verifica se faz pate do grupo Remote Desktop Users ou do grupo IIS_IUSR, verifica e contabiliza logons de usuários de acordo com os eventos do Event View.
# version 1.0 - 10/10/2024
# Last Modified: 14/10/2024
#===========================================================================

# ----------- funções complementares

# Function to get Admin user status
function Get-AdminUser {
	param([string] $username)
	$admingroup = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue
	$userType = "Local"
	
	foreach ($admin in $admingroup) {
		$name = $admin.name -split "\\"
		if($name[1] -eq $username){
			$userType = "Admin"
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

# Function to check if is an AD user
function Check-AdUser($username) { 
    $ad_User = $null 
	try {
		$ad_User = Get-ADUser -Identity $username
		return "Domain" 
	} catch {
		return "Unknown" 
	}
}

# Function to retrieve user AD SID
function Get-AdSid
{
	param([string]$pth, [array]$profileList)
	foreach($sid in $profileList) {
		if($pth -eq $sid.ProfileImagePath) {
			return $sid.PSChildName
		}
	}

	return ""
}


# Check if user belongs to group do IIS (IIS_IUSRS)
function Check-User-IIS {
	param([string] $username)

	$iisgroup = net localgroup IIS_IUSRS
	$descriptionCheck = ""

	foreach ($member in $iisgroup){
		if ($member.Trim() -eq $username) {
            $descriptionCheck = "`n`n [* Usuario Membro do Grupo: IIS_IUSRS *]"
            break
        }
	}

	return $descriptionCheck
}


# Check if user belongs to group do "Remote Desktop Users"
function Check-User-Remote {
	param([string] $username)

	$remotegroup = net localgroup "Remote Desktop Users"
	$descriptionCheck = ""

	foreach ($member in $remotegroup){
		if ($member.Trim() -eq $username) {
            $descriptionCheck = "`n`n [* Usuario Membro do Grupo: Remote Desktop Users *]"
            break
        }
	}

	return $descriptionCheck
}


# ----------- funções principais
#################################
#          Local User           #
#################################
# versões 2019 ou superiores
function WindowsRecents {
    $users = Get-LocalUser | Select *
    $pathUsers = "C:\Users"
    $allUsers = @()

    $startTime = (get-date).AddDays(-15)
    $logEvents = Get-Eventlog -LogName Security -after $startTime | where {$_.eventID -eq 4624}

    foreach ($user in $users) {
        if($user.Name -ne $null){
        
            $userType = Get-AdminUser $user.Name
            $path = "C:\Users\"+ $user.Name
            $folderSize = Get-Size $path
            if($user.Enabled -ne "False") { $userStatus = "Disabled" } else { $userStatus = "Enabled" }
            if($userType -eq "Local") { $userType = $user.PrincipalSource }

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

    #################################
    #            AD User            #
    #################################
    # Get computer account type connection
    $Dsregcmd = New-Object PSObject ; Dsregcmd /status | Where {$_ -match ' : '} | ForEach { $Item = $_.Trim() -split '\s:\s'; $Dsregcmd | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]','') -Value $Item[1] -EA SilentlyContinue }

    $profileListPath =  @("Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*")
    $profileList = Get-ItemProperty -Path $profileListPath -ErrorAction Ignore | Select ProfileImagePath, PSChildName

    $tmp = Get-ChildItem -Path $pathUsers | Select "Name"
    [System.Collections.ArrayList]$usersFolder = $tmp.Name

    while ($usersFolder -contains "Public") {
        $usersFolder.Remove("Public")
    }

    $usersAd = $usersFolder | Where-Object {$allUsers -notcontains $_}

    foreach ($userAd in $usersAd) {
        $path = "C:\Users\"+ $userAd

        $sid = Get-AdSid $path $profileList

        if($Dsregcmd.AzureAdJoined -eq "YES") {
            $folderSize = Get-Size $path
            $type = "AzureAD"
        }

        if($Dsregcmd.DomainJoined -eq "YES") {
            if (Get-Command Get-ADUser -errorAction SilentlyContinue) {
                $type = Check-AdUser -username $userAd
                $folderSize = Get-Size $path
            } else {
                $type = "Domain"
                $folderSize = Get-Size $path
            }
        }
        
        $xml += "<WINUSERS>`n"
        $xml += "<NAME>"+ $userAd +"</NAME>`n"
        $xml += "<TYPE>"+ $type +"</TYPE>`n"
        $xml += "<SIZE>"+ $folderSize +"</SIZE>`n"
        $xml += "<SID>"+ $sid +"</SID>`n"
        $xml += "</WINUSERS>`n"
    }

    return $xml
}


# versões 2016, 2012 e 2008
function WindowsOldAndLegacy {
    # Obtém todos os usuários locais e remove o cabeçalho e as linhas vazias
    $users = (wmic useraccount get name | Select-Object -Skip 1) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    $pathUsers = "C:\Users"
    $allUsers = @()

    $startTime = (get-date).AddDays(-15)
    $logEvents = Get-Eventlog -LogName Security -after $startTime | where {$_.eventID -eq 4624}


    # Itera sobre cada usuário
    foreach($user in $users) {
        if($user -and $user -ne 'The command completed successfully.'){
            try{

                # Obtém detalhes do usuário
                $userDetails = net user "$user"
                if (-not $userDetails) {
                    continue
                }

                # Nome do usuário
                $userName = $user

                ## ----- Eventos de Logon
                $numberConnexion = 0
                $workstation = ""
                $numberRemoteConnexion = 0
                $ipRemote ="" 

                foreach($userconnection in $logEvents){
                    #In local logon
                    if(($userconnection.ReplacementStrings[5] -eq $userName ) -and (($userconnection.ReplacementStrings[8] -eq 2) -or ($userconnection.ReplacementStrings[8] -eq 7))){
                        $numberConnexion = $numberConnexion + 1
                        $workstation = $userconnection.ReplacementStrings[11]
                    #In remote
                    }if (($userconnection.ReplacementStrings[5] -eq $userName ) -and ($userconnection.ReplacementStrings[8] -eq 10)){
                        $workstation = $userconnection.ReplacementStrings[11]
                        $numberRemoteConnexion = $numberRemoteConnexion + 1
                        $ipRemote = $userconnection.ReplacementStrings[18]
                    }
                }
                

                # Verifica o tipo de Usuário (Local ou Administrator)
                $isAdmin = net localgroup Administrators | Select-String -Pattern "\b$user\b" -Quiet
                $userType = if ($isAdmin) { "Administrador" } else { "Usuario Local" }
                
                # Status do usuário (Ativo/Inativo)
                $isActive = if ($userDetails -match "Account active\s+Yes") { "Ativo" } else { "Inativo" }

                # SSID do usuário
                $userSID = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='$userName'").SID
                if (-not $userSID) {
                    $userSID = "Nao disponivel"
                } 

                # Último logon do usuário
                $lastLogon = ($userDetails | Select-String "Last logon")
                if ($lastLogon -match "Never"){
                    $lastLogon = "Never"
                }
                else {
                    $ultimoLogon = $lastLogon -replace 'Last logon\s+', ''
                    try {                        
                        $lastLogon = [datetime]::ParseExact($ultimoLogon, 'M/d/yyyy h:mm:ss tt', $null).ToString('dd/MM/yyyy HH:mm:ss')
                    } catch {
                            $lastLogon = $ultimoLogon
                    }
                }

                # Caminho da pasta do usuário
                $userProfilePath = "C:\Users\$userName"
                if (-not (Test-Path $userProfilePath)) {
                    $userProfilePath = "Nao disponivel"
                    $folderSizeMB = "N/A"
                } else {
                    # Calcula o tamanho da pasta do usuário em MB
                    $folderSizeBytes = (Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue $userProfilePath | Measure-Object -Property Length -Sum).Sum
                    $folderSizeMB = [math]::Round($folderSizeBytes / 1MB, 2)
                }


                # Verifica se o usuário faz parte do grupo IIS_IUSRS
                $inIISGroup = net localgroup "IIS_IUSRS" | Select-String -Pattern "\b$user\b" -Quiet

                # Verifica se o usuário faz parte do grupo Remote Desktop Users
                $inRDGroup = net localgroup "Remote Desktop Users" | Select-String -Pattern "\b$user\b" -Quiet

                $userDescription =""
                $userDescription += if ($inIISGroup) { "[* Usuario Membro do Grupo: IIS_IUSRS *]`n" } else { "" }
                $userDescription += if ($inRDGroup) { "[* Usuario Membro do Grupo: Remote Desktop Users *]`n" } else { "" }


                $xml += "<WINUSERS>`n"
                $xml += "<NAME>"+ $userName +"</NAME>`n"
                $xml += "<TYPE>"+ $userType +"</TYPE>`n"
                $xml += "<SIZE>"+ $folderSizeMB +"</SIZE>`n"
                $xml += "<LASTLOGON>"+ $lastLogon +"</LASTLOGON>`n"
                $xml += "<DESCRIPTION>"+ $userDescription +"</DESCRIPTION>`n"
                $xml += "<STATUS>"+ $isActive +"</STATUS>`n"
                $xml += "<SID>"+ $userSID +"</SID>`n"
                $xml += "<USERCONNECTION>"+ $numberConnexion +"</USERCONNECTION>`n"
                $xml += "<NUMBERREMOTECONNECTION>"+ $numberRemoteConnexion +"</NUMBERREMOTECONNECTION>`n"
                $xml += "<IPREMOTE>"+ $ipRemote +"</IPREMOTE>`n"        
                $xml += "</WINUSERS>`n"

                $allUsers += $user.Name

            } catch {
                Write-Warning "Erro ao processar o usuario $user : $_"
            }
        }
    }

    return $xml
}


# extrai as informações de versão do S.O:
$versionOS = Get-WmiObject -Class Win32_OperatingSystem

# com base na versão é determinado o ano correspondente do S.O do Windows Server:
switch ($versionOS.Version) {
    {$_ -like "10.0*"} {
        # Usando o BuildNumber para diferenciar 2016, 2019 e 2022
        if ($versionOS.BuildNumber -ge 20348) {
            $yearOS = 2022 # Windows Server 2022
        } elseif ($versionOS.BuildNumber -ge 17763) {
            $yearOS = 2019 # Windows Server 2019
        } else {
            $yearOS = 2016 # Windows Server 2016
        }
        break
    }
    {$_ -like "6.3*"}  { $yearOS = 2012; break } # Windows Server 2012 R2
    {$_ -like "6.2*"}  { $yearOS = 2012; break } # Windows Server 2012
    {$_ -like "6.1*"}  { $yearOS = 2008; break } # Windows Server 2008 R2
    {$_ -like "6.0*"}  { $yearOS = 2006; break } # Windows Server 2006
    default { $yearOS = "Versão desconhecida" }
}


# start verificações
try {
    if ($yearOS -ge 2019) {
        $xml = WindowsRecents
    } else {
        $xml = WindowsOldAndLegacy
    }
} catch {
   Write-Warning "$yearOS - Erro na versão do SO`n"
   Write-Host $_
}

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
[Console]::WriteLine($xml)

