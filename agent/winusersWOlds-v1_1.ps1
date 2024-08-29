#===========================================================================
# Author: Danielly Brito
# Email: danielly.brito@umbler.com
# Plugin WinUsers 
# OCS Inventory Reports - For Versions: Windows Server 2008, 2012 R2 and 2016
# Description: Script que busca todos os usuários do sistema, verifica se é Administrator ou local, verifica se o user faz parte do grupo de Remote Desktop Users ou do grupo IIS_IUSRS além algumas outras informações. Recomendado principalmente para VMs que possuem Active Directory (AD)
# version 1.1 - 29/08/2024
# Last Modified: 29/08/2024
#===========================================================================

# Obtém todos os usuários locais e remove o cabeçalho e as linhas vazias
$users = (wmic useraccount get name | Select-Object -Skip 1) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

$pathUsers = "C:\Users"
$allUsers = @()

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

         # Verifica o tipo de Usuário (Local ou Administrator)
         $isAdmin = net localgroup Administrators | Select-String -Pattern "\b$user\b" -Quiet
         $userType = if ($isAdmin) { "Administrador" } else { "Usuário Local" }
         
         # Status do usuário (Ativo/Inativo)
         $isActive = if ($userDetails -match "Account active\s+Yes") { "Ativo" } else { "Inativo" }

         # SSID do usuário
         $userSID = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='$userName'").SID
         if (-not $userSID) {
            $userSID = "Não disponível"
         } 

         # Último logon do usuário
         $lastLogon = ($userDetails | Select-String "Last logon")
         if ($lastLogon -match "Never"){
            $lastLogon = "Never"
         }
         else {
            $ultimoLogon = $lastLogon -replace 'Last logon\s+', ''
            $lastLogon = [datetime]::ParseExact($ultimoLogon, 'M/d/yyyy h:mm:ss tt', $null).ToString('dd/MM/yyyy HH:mm:ss')
         }

         # Caminho da pasta do usuário
         $userProfilePath = "C:\Users\$userName"
         if (-not (Test-Path $userProfilePath)) {
            $userProfilePath = "Não disponível"
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
         $xml += "</WINUSERS>`n"

         $allUsers += $user.Name

      } catch {
         Write-Warning "Erro ao processar o usuário $user : $_"
      }
   }
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::WriteLine($xml)
