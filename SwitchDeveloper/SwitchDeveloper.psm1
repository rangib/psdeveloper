$SolrPath = "$($PSScriptRoot)\solr"

# Testing Methods

function Test-IsAdministrator {

    param()

    process
    {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        return (New-Object System.Security.Principal.WindowsPrincipal $user).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

}

function Test-JavaInstalled {

    param()

    process
    {
        return (@(Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\JavaSoft\Java Development Kit' | Select-Object -ExpandProperty Name).Count -gt 0)
    }

}

# Server Manager Methods

function Export-InstalledSoftware {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$OutFile,
        [String]$ComputerName = [String]::Empty
    )

    begin
    {
        Import-Module -Name ServerManager

        if ([String]::IsNullOrEmpty($ComputerName))
        {
            $ComputerName = $env:COMPUTERNAME
        }
    }

    process
    {
        $PaddingLeft = -60
        $PaddingRight = 60
        $FeatureDetails = New-Object System.Collections.ArrayList
        $Seperator = [String]::Format("# {0}", "-" * (($PaddingRight * 2) + 1))

        New-Item -Path $OutFile -ItemType File -Force | Out-Null

        [String]::Format("# {0,$($PaddingLeft)} {1,$($PaddingRight)}", "Display Name", "Name") | Add-Content $OutFile
        
        $Seperator | Add-Content $OutFile

        $InstalledFeatures = Get-WindowsFeature -Computer $ComputerName | Where-Object { $_.Installed -eq $true }
        $InstalledFeatures | Select-Object -Property DisplayName, Name | %{ $FeatureDetails.Add([String]::Format("# {0,$($PaddingLeft)} {1,$($PaddingRight)}", $_.DisplayName, $_.Name)) | Out-Null }

        $FeatureDetails -join [Environment]::NewLine | Add-Content $OutFile

        $Seperator | Add-Content $OutFile

        [Environment]::NewLine | Add-Content $OutFile

        try
        {
            "Add-WindowsFeature $([String]::Join(", ", ($InstalledFeatures | Select-Object -ExpandProperty Name)))" | Add-Content $OutFile
        }
        catch
        {
            
        }
    }

}

# Solr Methods

function New-SolrIndex {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$IndexFilename,
        [String]$SourceIndexPath,
        [String]$OutputIndexPath
    )

    begin
    {
        $IndexSource = [String]::Empty
        $IndexTarget = [String]::Empty

        if ([String]::IsNullOrEmpty($SourceIndexPath))
        {
            $IndexSource = Join-Path -Path $SolrPath -ChildPath "default-index"
        }
        else
        {
            $IndexSource = $SourceIndexPath
        }

        if ([String]::IsNullOrEmpty($OutputIndexPath))
        {
            $IndexTarget = Join-Path -Path (Get-Location).Path -ChildPath "generated-indexes"
        }
        else
        {
            $IndexTarget = $OutputIndexPath
        }

        if (!(Test-Path -Path $IndexTarget))
        {
            New-Item -ItemType Directory -Path $IndexTarget | Out-Null
        }
    }

    process
    {
        $IndexContent = [String]::Empty

        if (Test-Path -Path $IndexFilename)
        {
            $IndexContent = Get-Content -Path $IndexFilename
        }
        else
        {
            Throw "Index filename `"$($IndexFilename)`" not found"
        }

        if (!([String]::IsNullOrEmpty($IndexContent)))
        {
            if (Test-Path -Path $IndexSource)
            {
                foreach ($Index in $IndexContent)
                {
                    $IndexPath = Join-Path -Path $IndexTarget -ChildPath $Index

                    if (!(Test-Path -Path $IndexPath))
                    {
                        try
                        {
                            Copy-Item -Path $IndexSource -Recurse -Destination $IndexPath -Container
                        }
                        catch
                        {
                            Write-Host "Unable to create index `"$($Index)`"" -ForegroundColor Red
                            continue
                        }

                        Write-Host "Created index `"$($Index)`"" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host "Skipping index `"$($Index)`", it already exists!" -ForegroundColor Yellow
                    }
                }
            }
        }
        else
        {
            Throw "Index file `"$($IndexFilename)`" is empty!"
        }
    }

}

function New-SolrCore {

    param(
        [String]$Scheme = "http",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Hostname,
        [int]$Port = 8983,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$IndexFilename
    )

    process
    {
        $Exceptions = @{}
        $IndexContent = [String]::Empty

        if (Test-Path -Path $IndexFilename)
        {
            $IndexContent = Get-Content -Path $IndexFilename
        }
        else
        {
            Throw "Index filename `"$($IndexFilename)`" not found"
        }

        if (!([String]::IsNullOrEmpty($IndexContent)))
        {
            foreach ($Index in $IndexContent)
            {
                $Response = [String]::Empty

                try
                {
                    $Response = Invoke-WebRequest -Uri "$($Scheme)://$($Hostname):$($Port)/solr/admin/cores?action=CREATE&name=$($Index)&instanceDir=$($Index)&config=solrconfig.xml&schema=schema.xml"
                }
                catch
                {
                    $Exceptions += @{ $Index = $_.Exception.Message }

                    Write-Host "Something went wrong creating the core for index `"$($Index)`"" -ForegroundColor Red
                    continue
                }

                if ($Response -ne $null)
                {
                    Write-Host "Created core `"$($Index)`" on Solr instance `"$($Scheme)://$($Hostname):$($Port)`""
                }

            }

            if ($Exceptions.Count -gt 0)
            {
                foreach ($Exception in $Exceptions)
                {
                    Write-Host "$($Exception.Key) - $($Exceptions[$Exception.Key])" -ForegroundColor Red
                }
            }
        }
        else
        {
            Throw "Index file `"$($IndexFilename)`" is empty!"
        }
    }

}

function New-SolrCollection {

    param(
        [String]$Scheme = "http",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Hostname,
        [int]$Port = 8983,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$IndexFilename,
        [int]$NumberOfShards = 1,
        [int]$ReplicationFactor = 3
    )

    process
    {
        $Exceptions = @{}
        $IndexContent = [String]::Empty

        if (Test-Path -Path $IndexFilename)
        {
            $IndexContent = Get-Content -Path $IndexFilename
        }
        else
        {
            Throw "Index filename `"$($IndexFilename)`" not found"
        }

        if (!([String]::IsNullOrEmpty($IndexContent)))
        {
            foreach ($Index in $IndexContent)
            {
                $Response = [String]::Empty

                try
                {
                    $Response = Invoke-WebRequest -Uri "$($Scheme)://$($Hostname):$($Port)/solr/admin/collections?action=CREATE&name=$($Index)&collection.configName=$($Index)&numShards=$($NumberOfShards)&replicationFactor=$($ReplicationFactor)"
                }
                catch
                {
                    $Exceptions += @{ $Index = $_.Exception.Message }

                    Write-Host "Something went wrong creating the collection for index `"$($Index)`"" -ForegroundColor Red
                    continue
                }

                if ($Response -ne $null)
                {
                    Write-Host "Created collection `"$($Index)`" on Solr instance `"$($Scheme)://$($Hostname):$($Port)`""
                }

            }

            if ($Exceptions.Count -gt 0)
            {
                foreach ($Exception in $Exceptions)
                {
                    Write-Host "$($Exception.Key) - $($Exceptions[$Exception.Key])" -ForegroundColor Red
                }
            }
        }
        else
        {
            Throw "Index file `"$($IndexFilename)`" is empty!"
        }
    }

}

function Install-ZooKeeperSolrConfig {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$IndexFilename,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ZooKeeperEnsemble,
        [String]$SourceIndexPath
    )

    begin
    {
        if (!(Test-JavaInstalled))
        {
            Throw "Java does not appear to be installed. Quitting"
        }

        $IndexSource = [String]::Empty
        $ZooKeeperCliCmd = Join-Path -Path $SolrPath -ChildPath "scripts\zkcli.bat"

        if ([String]::IsNullOrEmpty($SourceIndexPath))
        {
            $IndexSource = Join-Path -Path (Get-Location).Path -ChildPath "generated-indexes"
        }
        elseif (Test-Path -Path $SourceIndexPath)
        {
            $IndexSource = $SourceIndexPath
        }
        else
        {
            Throw "Invalid path to indexes provided ($($SourceIndexPath))"
        }
    }

    process
    {
        $Exceptions = @{}
        $IndexContent = [String]::Empty

        if (Test-Path -Path $IndexFilename)
        {
            $IndexContent = Get-Content -Path $IndexFilename
        }
        else
        {
            Throw "Index filename `"$($IndexFilename)`" not found"
        }

        if (!([String]::IsNullOrEmpty($IndexContent)))
        {
            foreach ($Index in $IndexContent)
            {
                $IndexPath = Join-Path -Path $IndexSource -ChildPath $Index

                if (Test-Path -Path $IndexPath)
                {
                    $IndexConfigPath = Join-Path -Path $IndexPath -ChildPath "conf"

                    if (Test-Path -Path $IndexConfigPath)
                    {
                        $ZooKeeperCliCmdArgs = "-zkhost $($ZooKeeperEnsemble -Join ",") -cmd upconfig -confdir $($IndexConfigPath) -confname $($Index)"

                        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $pInfo.FileName = $ZooKeeperCliCmd
                        $pInfo.Arguments = $ZooKeeperCliCmdArgs
                        $pInfo.WindowStyle = "Hidden"
                        $pInfo.RedirectStandardError = $true
                        $pInfo.RedirectStandardOutput = $true

                        $p = New-Object System.Diagnostics.Process
                        $p.StartInfo = $Info

                        try
                        {
                            $p.Start() | Out-Null
                            $p.WaitForExit()

                            $Exceptions += { $Index = $p.StandardError.ReadToEnd() }
                        }
                        catch
                        {
                            Write-Host "Something went wrong uploading the configuration to ZooKeeper Ensemble $($ZooKeeperEnsemble -Join ",")" -ForegroundColor Red

                            if ($Exceptions.ContainsKey($Index))
                            {
                                $Exceptions[$Index] += $_.Exception.Message
                            }

                            continue
                        }

                        Write-Host "Uploaded configuration for index `"$($Index)`"" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host "Not able to find default solr configuration folder for index `"$($Index)`". Skipping." -ForegroundColor Yellow
                    }
                }
                else
                {
                    Write-Host "`"$($Index)`" specified in `"$($IndexFilename)`" but could not be found. Skipping." -ForegroundColor Yellow
                }
            }

            if ($Exceptions.Count -gt 0)
            {
                foreach ($Exception in $Exceptions)
                {
                    Write-Host "$($Exception.Key) - $($Exceptions[$Exception.Key])" -ForegroundColor Red
                }
            }
        }
        else
        {
            Throw "Index file `"$($IndexFilename)`" is empty!"
        }
    }

}

# AES Encryption Methods

function New-AesManagedObject {

	param(
		$Key,
		$IV
	)

	process
	{
		$AesManaged = New-Object System.Security.Cryptography.AesManaged
		$AesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$AesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
		$AesManaged.BlockSize = 128
		$AesManaged.KeySize = 256
		
		if ($Key)
		{
			if ($Key.GetType().Name -eq "String")
			{
				$AesManaged.Key = [System.Convert]::FromBase64String($Key)
			}
			else
			{
				$AesManaged.Key = $Key
			}
		}

		if ($IV)
		{
			if ($IV.GetType().Name -eq "String")
			{
				$AesManaged.IV = [System.Convert]::FromBase64String($IV)
			}
			else
			{
				$AesManaged.IV = $IV
			}
		}

		return $AesManaged
	}

}

function New-AesKey {

	param()

	process
	{
		$AesManaged = New-AesManagedObject
		$AesManaged.GenerateKey()

		return [System.Convert]::ToBase64String($AesManaged.Key)
	}

}

function ConvertTo-AesString {

	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Key,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$InputObject
	)

	begin
	{
		$Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputObject)
		$AesManaged = New-AesManagedObject -Key $Key
		$Encryptor = $AesManaged.CreateEncryptor()
	}

	process
	{
		$EncryptedData = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
		[byte[]]$FullData = $AesManaged.IV + $EncryptedData

		$AesManaged.Dispose()

		return [System.Convert]::ToBase64String($FullData)
	}

}

function ConvertFrom-AesString {

	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Key,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$InputObject
	)

	begin
	{
		$Bytes = [System.Convert]::FromBase64String($InputObject)
		$IV = $Bytes[0..15]
		$AesManaged = New-AesManagedObject -Key $Key -IV $IV
		$Decryptor = $AesManaged.CreateDecryptor()
	}

	process
	{
		$DecryptedData = $Decryptor.TransformFinalBlock($Bytes, 16, $Bytes.Length - 16)
		$AesManaged.Dispose()

		return [System.Text.Encoding]::UTF8.GetString($DecryptedData).Trim([char]0)
	}

}

# SSL Methods

function New-WildcardSslCertificate {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Domain,
        [String]$CertificateStore = "cert:\LocalMachine\My"
    )

    process
    {
        try
        {
            New-SelfSignedCertificate -DnsName "*.$($Domain)" -CertStoreLocation $CertificateStore
        }
        catch
        {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

}

# Registry Methods

function Get-RegistryKeyValue {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Key,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Value
    )

    process
    {
        return Get-ItemProperty -Path "Registry::$($Key)" | Select-Object -ExpandProperty $Value
    }

}

function Get-RegistryKeyChildren {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Key
    )

    process
    {
        return Get-ChildItem -Path "Registry::$($Key)" -Recurse
    }

}

function Set-RegistryKeyPropertyValue {

	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Key,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Property,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,
		[ValidateSet("Binary","DWord","ExpandString","MultiString","String","QWord")]
		[String]$DataType = "String"
	)

	begin
	{
		$RegistryPath = "Registry::$($Key)"
	}

	process
	{
		if (!(Test-Path -Path "Registry::$($Key)"))
		{
			New-Item -Path "Registry::$($Key)" | Out-Null
		}

        if (Test-Path -Path "Registry::$($Key)\$($Property)")
        {
            Set-ItemProperty -Path $RegistryPath -Name $Property -Value $Value -Type $DataType
        }
        else
        {
            New-ItemProperty -Path $RegistryPath -Name $Property -Value $Value -PropertyType $DataType
        }
	}

}

function Set-LoopbackValue {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1)]
        [int]$LoopbackValue
    )

    begin
    {
        if (!(Test-IsAdministrator))
        {
            Write-Host "You must be an administrator to execute this method" -ForegroundColor Red
            exit
        }

		$RegistryLoopbackPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\"
		$RegistryLoopbackProperty = "DisableLoopbackCheck"
    }

    process
    {
        Set-RegistryKeyPropertyValue -Key $RegistryLoopbackPath -Property $RegistryLoopbackProperty -Value $LoopbackValue -DataType DWord
    }

}

function Disable-Loopback {

    param()

    process
    {
        try
        {
            Set-LoopbackValue -LoopbackValue 1
        }
        catch
        {

        }
    }

}

function Enable-Loopback {

    param()

    process
    {
        try
        {
            Set-LoopbackValue -LoopbackValue 0
        }
        catch
        {

        }
    }

}

function Get-SqlServerVersions {

    param()

    begin
    {
        $BaseKey = "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server"
        $InstancesRK = "$($BaseKey)\Instance Names"
        $InstancesRP = "MSSQLSERVER"
    }

    process
    {

        Get-RegistryKeyChildren -Key $InstancesRK | Where-Object { $_.Name -contains "SQL" } | %{
            Get-RegistryKeyChildren -Key "$($InstancesRK)\$($_.Name)" | %{
                Write-Host $_.GetType()
            }
        }

        #foreach ($instance in (Get-RegistryKeyValue -Key $InstancesRK -Value $InstancesRP))
        #{
        #    $InstanceK = "$($BaseKey)\$($instance)\MSSQLServer\CurrentVersion"
        #    $InstanceP = "CurrentVersion"
        #
        #    Write-Host "$($instance) $(Get-RegistryKeyValue $InstanceK -Value $InstanceP)"
        #}
    }

}

# Google Drive Database Methods

function Get-SwitchSyncClientProperties {

    process
    {
        $RegistryKey = "HKLM\SOFTWARE\Switch\SwitchSync"

        return @{
            
            "TokenRequestUri" = Get-RegistryKeyValue -Key $RegistryKey -Value "TokenRequestUri";

            "DriveApiUri" = Get-RegistryKeyValue -Key $RegistryKey -Value "DriveApiUri";
            "DriveApiTeamDrivesUri" = Get-RegistryKeyValue -Key $RegistryKey -Value "DriveApiTeamDrivesUri";

            "RefreshToken" = Get-RegistryKeyValue -Key $RegistryKey -Value "RefreshToken";
            "RefreshTokenProperty" = Get-RegistryKeyValue -Key $RegistryKey -Value "RefreshTokenProperty";

            "ClientId" = Get-RegistryKeyValue -Key $RegistryKey -Value "ClientId";
            "ClientIdProperty" = Get-RegistryKeyValue -Key $RegistryKey -Value "ClientIdProperty";

            "ClientSecret" = Get-RegistryKeyValue -Key $RegistryKey -Value "ClientSecret";
            "ClientSecretProperty" = Get-RegistryKeyValue -Key $RegistryKey -Value "ClientSecretProperty";

            "GrantType" = Get-RegistryKeyValue -Key $RegistryKey -Value "GrantType";
            "GrantTypeProperty" = Get-RegistryKeyValue -Key $RegistryKey -Value "GrantTypeProperty";
        }
    }

}

function Get-SwitchSyncClientOAuthToken {
    
    begin
    {
        $ClientProps = Get-SwitchSyncClientProperties
    }

    process
    {
        $AuthRequest = "$($ClientProps.RefreshTokenProperty)=$($ClientProps.RefreshToken)&$($ClientProps.ClientIdProperty)=$($ClientProps.ClientId)&$($ClientProps.ClientSecretProperty)=$($ClientProps.ClientSecret)&$($ClientProps.GrantTypeProperty)=$($ClientProps.GrantType)"
        $AuthResponse = Invoke-RestMethod -Method Post -Uri $ClientProps.TokenRequestUri -ContentType "application/x-www-form-urlencoded" -Body $AuthRequest

        return $AuthResponse.access_token
    }

}

function Get-SwitchSyncClientOAuthHeader {

    process
    {
        return @{ "Authorization" = "Bearer $(Get-SwitchSyncClientOAuthToken)" };
    }

}

function Invoke-SwitchSyncClient {

	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Uri,
		[String]$Method = "GET",
		[String]$OutFile
	)

	process
	{
		if ([String]::IsNullOrEmpty($OutFile))
		{
			return Invoke-RestMethod -Method "$($Method)" -Uri "$($Uri)" -Headers (Get-SwitchSyncClientOAuthHeader)
		}
		else
		{
			return Invoke-RestMethod -Method "$($Method)" -Uri "$($Uri)" -Headers (Get-SwitchSyncClientOAuthHeader) -OutFile "$($OutFile)"
		}
	}

}

function Get-SwitchSyncClientTeamDriveId {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ClientName
    )

    begin
    {
        $ClientProps = Get-SwitchSyncClientProperties
    }

    process
    {
        $Request = Invoke-SwitchSyncClient -Uri "$($ClientProps.DriveApiTeamDrivesUri)?useDomainAdminAccess=true&q=name = '$($ClientName)'"

        $TeamDriveId = [String]::Empty

        if ($Request.teamDrives.Count -gt 0)
        {
            $TeamDriveId = $Request.teamDrives.id
        }

        if (!([String]::IsNullOrEmpty($TeamDriveId)))
        {
            Write-Verbose "Found $($ClientName) Team Drive (Id: $($TeamDriveId))"
        }
        elseif ([String]::IsNullOrEmpty($TeamDriveId))
        {
            Write-Verbose "Could not find $($ClientName) Team Drive"
        }

        return $TeamDriveId
    }

}

function Get-SwitchSyncClientTeamDriveFoldersForClient {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ClientName
    )

    begin
    {
        $ClientProps = Get-SwitchSyncClientProperties
        $TeamDriveId = Get-SwitchSyncClientTeamDriveId -ClientName $ClientName
    }

    process
    {
        $Request = Invoke-SwitchSyncClient -Uri "$($ClientProps.DriveApiUri)?corpora=teamDrive&includeTeamDriveItems=true&q=mimeType = 'application/vnd.google-apps.folder'&supportsTeamDrives=true&teamDriveId=$($TeamDriveId)"
        $TeamDriveFolders = New-Object System.Collections.ArrayList

        if ($Request.files.Count -gt 0)
        {
            foreach ($Folder in $Request.files)
            {
                $TeamDriveFolders.Add([PSCustomObject]@{ "Id" = $Folder.id; "TeamDriveId" = $TeamDriveId; "Name" = $Folder.name; }) | Out-Null
            }
        }

        if ($TeamDriveFolders.Count -gt 0)
        {
            Write-Verbose "Found folders ($(($TeamDriveFolders | Select -ExpandProperty Name) -join ", ")) for $($ClientName) Team Drive"
        }
        elseif ($TeamDriveFolders.Count -le 0)
        {
            Write-Verbose "Could not find any folders for $($ClientName) Team Drive"
        }

        return $TeamDriveFolders
    }

}

function Get-SwitchSyncClientFolderFiles {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ClientName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Dev","DevQA","QA","UAT","Prod")]
        [String]$Environment
    )

    begin
    {
        $ClientProps = Get-SwitchSyncClientProperties
        $ClientEnvironmentFolder = Get-SwitchSyncClientTeamDriveFoldersForClient -ClientName $ClientName | Where-Object { $_.Name -eq $Environment } | Select-Object -First 1
    }

    process
    {
        $Request = Invoke-SwitchSyncClient -Uri "$($ClientProps.DriveApiUri)?corpora=teamDrive&includeTeamDriveItems=true&q='$($ClientEnvironmentFolder.Id)' in parents and mimeType != 'application/vnd.google-apps.folder'&supportsTeamDrives=true&teamDriveId=$($ClientEnvironmentFolder.TeamDriveId)"
        
        $ClientFolderFiles = New-Object System.Collections.ArrayList

        if ($Request.files.Count -gt 0)
        {
            foreach ($File in $Request.files)
            {
                $ClientFolderFiles.Add([PSCustomObject]@{ "TeamDriveId" = $ClientEnvironmentFolder.TeamDriveId; "ParentId" = $ClientEnvironmentFolder.Id; "Id" = $File.id; "Name" = $File.name; "MimeType" = $File.mimeType; }) | Out-Null
            }
        }

        if ($ClientFolderFiles.Count -gt 0)
        {
            Write-Verbose "Found files ($(($ClientFolderFiles | Select -ExpandProperty Name) -join ", ")) for $($ClientName) Team Drive (Environment: $($Environment))"
        }
        elseif ($ClientFolderFiles.Count -le 0)
        {
            Write-Verbose "Could not find any files for $($ClientName) Team Drive (Environment: $($Environment))"
        }

        return $ClientFolderFiles
    }

}

function Get-SwitchSyncClientDatabaseBackups {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ClientName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Dev","DevQA","QA","UAT","Prod")]
        [String]$Environment,
        [String]$OutLocation,
        [bool]$Latest = $true,
        [String]$TimeStamp
    )

    begin
    {
        $ClientProps = Get-SwitchSyncClientProperties
        $ClientEnvironmentFolderFiles = Get-SwitchSyncClientFolderFiles -ClientName $ClientName -Environment $Environment

        if ([String]::IsNullOrEmpty($OutLocation))
        {
            $OutLocation = Get-Location
        }

        $FetchFiles = @{}
        
        $ClientEnvironmentFolderFiles | ForEach-Object {
            if ($_.Name -match "(\d{8}) - .*")
            {
                if (!($FetchFiles.ContainsKey($Matches[1])))
                {
                    $FetchFiles += @{
                        $Matches[1] = New-Object System.Collections.ArrayList
                    }
                }

                $FetchFiles[$Matches[1]].Add($_) | Out-Null
            }
        }

        $FetchFiles = $FetchFiles.GetEnumerator() | Sort -Property Name -Descending
        $FilesToRetrieve = New-Object System.Collections.ArrayList

        if ($Latest -eq $true)
        {
            $FilesToRetrieve = $FetchFiles.GetEnumerator() | Select -First 1 | Select-Object -ExpandProperty Value
        }
        elseif ($Latest -eq $false -and !([String]::IsNullOrEmpty($TimeStamp)))
        {
            if ($FetchFiles.ContainsKey($TimeStamp))
            {
                $FilesToRetrieve = $FetchFiles.GetEnumerator() | ?{ $_.Key -eq $TimeStamp } | Select-Object -ExpandProperty Value
            }
            else
            {
                Write-Host "Couldn't find the requested file set: $($TimeStamp)" -ForegroundColor Red
            }
        }
    }

    process
    {
        $FilesToRetrieve | %{
            Invoke-SwitchSyncClient -Uri "$($ClientProps.DriveApiUri)/$($_.Id)?alt=media&supportsTeamDrives=true" -OutFile "$($OutLocation)\$($_.Name)"
        }

		return ($FilesToRetrieve | Select-Object -ExpandProperty Name)
    }

}

function Restore-SwitchSyncClientDatabases {

    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ClientName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Dev","DevQA","QA","UAT","Prod")]
        [String]$Environment,
        [String]$OutLocation,
        [bool]$Latest = $true,
        [String]$TimeStamp
    )

	begin
	{
		$RetrievedFiles = @()

		if ([String]::IsNullOrEmpty($OutLocation))
		{
			$OutLocation = Get-RegistryKeyValue -Key "HKLM\Software\Microsoft\MSSQLServer\MSSQLServer" -Value "BackupDirectory"
		}

        Write-Host $OutLocation
        break

		if ($Latest -eq $true)
		{
			$RetrievedFiles = Get-SwitchSyncClientDatabaseBackups -ClientName $ClientName -Environment $Environment -OutLocation $OutLocation
		}
		elseif (($Latest -eq $false) -and (!([String]::IsNullOrEmpty($TimeStamp))))
		{
			$RetrievedFiles = Get-SwitchSyncClientDatabaseBackups -ClientName $ClientName -Environment $Environment -OutLocation $OutLocation -Latest $false -TimeStamp $TimeStamp
		}
	}

	process
	{
		
	}

}

# Sitecore Configuration Methods

function Set-SitecoreDefaultAdminPassword {

    param(
        [ValidateNotNullOrEmpty()]
        [String]$ServerName = "localhost",
        [String]$CoreDatabaseName = "Sitecore_Core",
        [String]$AdminUsername = "sitecore\Admin"
    )

    process
    {
        try
        {
            Invoke-Sqlcmd -Query "UPDATE [$($CoreDatabaseName)].[dbo].[aspnet_Membership] SET [Password] = 'qOvF8m8F2IcWMvfOBjJYHmfLABc=', [PasswordSalt] = 'OM5gu45RQuJ76itRvkSPFw==', [IsApproved] = '1', [IsLockedOut] = '0' WHERE UserId IN (SELECT UserId FROM [$($CoreDatabaseName)].[dbo].[aspnet_Users] WHERE UserName = '$($AdminUsername)')" -ServerInstance $ServerName
        }
        catch
        {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

}

function Clear-SitecoreQueues {

	param(
		[DateTime]$ClearFrom = $null,
		[ValidateNotNullOrEmpty()]
		[String]$ClientName,
        [ValidateNotNullOrEmpty()]
        [String]$ServerName = "localhost",
		[ValidateNotNullOrEmpty()]
		[String]$DatabaseNameFormat = "{0}_Sitecore_{1}",
		[ValidateNotNullOrEmpty()]
		[ValidateSet("History","PublishQueue","EventQueue","All")]
		[String]$ClearQueues = "All",
		[ValidateNotNullOrEmpty()]
		[ValidateSet("Core", "Web", "Master", "All")]
		[String]$ClearDatabases = "All"
	)

	begin
	{
		if ($ClearFrom -eq $null)
		{
			$ClearFrom = [DateTime]::Now.AddHours(-12)
		}

		$QueuesToClear = New-Object System.Collections.ArrayList
		$DatabasesToClear = New-Object System.Collections.ArrayList

		if ($ClearQueues -eq "All")
		{
			$QueuesToClear.Add("History") | Out-Null
			$QueuesToClear.Add("PublishQueue") | Out-Null
			$QueuesToClear.Add("EventQueue") | Out-Null
		}
		else
		{
			$QueuesToClear.Add($ClearQueues) | Out-Null
		}

		if ($ClearDatabases -eq "All")
		{
			$DatabasesToClear.Add("Core") | Out-Null
			$DatabasesToClear.Add("Web") | Out-Null
			$DatabasesToClear.Add("Master") | Out-Null
		}
		else
		{
			$DatabasesToClear.Add($ClearDatabases) | Out-Null
		}
	}

	process
	{
		$DatabasesToClear | ForEach-Object {

			$DatabaseName = $_

			$QueuesToClear | ForEach-Object {

				$SqlQuery = [String]::Empty
				$QueueName = $_
				
				if ($QueueName -eq "PublishQueue")
				{
					$SqlQuery = "DELETE FROM [$([String]::Format($DatabaseNameFormat, $ClientName, $DatabaseName))].[dbo].[$($QueueName)] WHERE [Date] < '$($ClearFrom)'"
				}
				else
				{
					$SqlQuery = "DELETE FROM [$([String]::Format($DatabaseNameFormat, $ClientName, $DatabaseName))].[dbo].[$($QueueName)] WHERE [Created] < '$($ClearFrom)'"
				}
				
				Invoke-Sqlcmd -Query $SqlQuery -ServerInstance $ServerName

			}
		}
	}

}

function Compare-SitecoreConfiguration {

    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        [string]$Delimiter = ",",
        [Parameter(Mandatory=$true)]
        [ValidateSet("Lucene","Solr","Azure")]
        [string]$SearchProvider = "Lucene",
        [Parameter(Mandatory=$true)]
        [ValidateSet("CD","CM","Processing","CM-Processing","Reporting")]
        [string]$Role = "CD",
        [Parameter(Mandatory=$true)]
        [string]$WebsitePath
    )

    begin
    {
        $SplitOptions = [System.StringSplitOptions]::RemoveEmptyEntries

        $WebsitePath = [string]::Join("\", $WebsitePath.Split("\", $SplitOptions))

        $EnabledExt = ".config"
        $SourcePath = "$($WebsitePath)\App_Config"
        $BackupPath = "$($WebsitePath)\Backup.zip"

        if (Test-Path -Path $BackupPath)
        {
            Remove-Item -Path $BackupPath -Force
        }

        Add-Type -Assembly "System.IO.Compression.FileSystem"
        [IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $BackupPath)

        $SearchProviderColumn = "Search Provider Used"
        $SearchProviderValue = [string]::Empty

        if ($SearchProvider -eq "Solr")
        {
            $SearchProviderValue = "Solr is used"
        }
        elseif ($SearchProvider -eq "Azure")
        {
            $SearchProviderValue = "Azure is used"
        }
        else
        {
            $SearchProviderValue = "Lucene is used"
        }

        $RoleValue = [string]::Empty

        if ($Role -eq "CM")
        {
            $RoleValue = "Content Management (CM)"
        }
        elseif ($Role -eq "Processing")
        {
            $RoleValue = "Processing"
        }
        elseif ($Role -eq "CM-Processing")
        {
            $RoleValue = "CM + Processing"
        }
        elseif ($Role -eq "Reporting")
        {
            $RoleValue = "Reporting"
        }
        else
        {
            $RoleValue = "Content Delivery (CD)"
        }

        $Configs = Import-CSV -Path $CsvPath -Delimiter $Delimiter
        $Configs = $Configs | Where-Object { ($_.$SearchProviderColumn -eq $SearchProviderValue -or $_.$SearchProviderColumn -eq [string]::Empty) }
    }

    process
    {
        $DisabledConfigs = $Configs | Where-Object { $_.$RoleValue -eq "Disable" }

        foreach ($DisabledConfig in $DisabledConfigs)
        {
            $FilePath = [string]$DisabledConfig.("File Path")
            $FilePath = [string]::Join("\", $FilePath.Replace("website\", $null).Split("\", $SplitOptions))
            $FileName = [string]$DisabledConfig.("Config file name")

            $EnabledFileName = $FileName.Substring(0, ($FileName.LastIndexOf($EnabledExt) + $EnabledExt.Length))

            if (Test-Path -Path "$($WebsitePath)\$($FilePath)")
            {
                $TargetPath = "$($WebsitePath)\$($FilePath)"
                $TargetFile = Get-ChildItem -Path "$($TargetPath)" -File -Filter "$($EnabledFileName)*"

                if ($TargetFile -ne $null)
                {
                    Rename-Item -Path "$($TargetPath)\$($TargetFile.Name)" -NewName "$($TargetPath)\$($EnabledFileName)" -Force -ErrorAction SilentlyContinue
                }

                if (Test-Path -Path "$($TargetPath)\$($EnabledFileName)")
                {
                    Rename-Item -Path "$($TargetPath)\$($EnabledFileName)" -NewName "$($TargetPath)\$($EnabledFileName).disabled" -Force -ErrorAction SilentlyContinue
                }

                Write-Host "Disabled: $($TargetPath)\$($EnabledFileName)" -ForegroundColor Yellow
            }
        }

        $EnabledConfigs = $Configs | Where-Object { $_.$RoleValue -eq "Enable" }

        foreach ($EnabledConfig in $EnabledConfigs)
        {
            $FilePath = [string]$EnabledConfig.("File Path")
            $FilePath = [string]::Join("\", $FilePath.Replace("website\", $null).Split("\", $SplitOptions))
            $FileName = [string]$EnabledConfig.("Config file name")

            $EnabledFileName = $FileName.Substring(0, ($FileName.LastIndexOf($EnabledExt) + $EnabledExt.Length))

            if (Test-Path -Path "$($WebsitePath)\$($FilePath)")
            {
                $TargetPath = "$($WebsitePath)\$($FilePath)"
                $TargetFile = Get-ChildItem -Path "$($TargetPath)" -File -Filter "$($EnabledFileName)*"

                if ($TargetFile -ne $null)
                {
                    Rename-Item -Path "$($TargetPath)\$($TargetFile.Name)" -NewName "$($TargetPath)\$($EnabledFileName)" -Force -ErrorAction SilentlyContinue
                }

                if (Test-Path -Path "$($TargetPath)\$($EnabledFileName)")
                {
                    Rename-Item -Path "$($TargetPath)\$($EnabledFileName)" -NewName "$($TargetPath)\$($EnabledFileName)" -Force -ErrorAction SilentlyContinue
                }

                Write-Host "Enabled: $($TargetPath)\$($EnabledFileName)" -ForegroundColor Green
            }
        }

    }

}

# Visual Studio Methods

function New-PublishProfiles {

	param(
	    [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$SourceFolderPath,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$PublishProfileName,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$GlobalPublishProfilePath
	)

	process
	{
		$ChildWebProjects = Get-ChildItem -Path $SourceFolderPath -Recurse -Filter "*.csproj" | %{
    
			$projectFolder = $_.DirectoryName
			$projectPropertiesFolder = "$($projectFolder)\Properties"
			$projectPublishProfilesFolder = "$($projectPropertiesFolder)\PublishProfiles"
			$projectPublishProfile = "$($projectPublishProfilesFolder)\$($PublishProfileName).pubxml"

			if (!(Test-Path -Path $projectPropertiesFolder))
			{
				New-Item -Path $projectPropertiesFolder -ItemType Directory
			}

			if (!(Test-Path -Path $projectPublishProfilesFolder))
			{
				New-Item -Path $projectPublishProfilesFolder -ItemType Directory
			}

			$xmlWriter = New-Object System.Xml.XmlTextWriter($projectPublishProfile, [System.Text.Encoding]::UTF8)
			$xmlWriter.Formatting = "Indented"
			$xmlWriter.Indentation = "4"

			$xmlWriter.WriteStartDocument()

			$xmlWriter.WriteStartElement("Project", "http://schemas.microsoft.com/developer/msbuild/2003")
    
				$xmlWriter.WriteAttributeString($null, "ToolsVersion", $null, "4.0")

				$xmlWriter.WriteStartElement("Import")
				$xmlWriter.WriteAttributeString($null, "Project", $null, $GlobalPublishSettingsFilePath)
				$xmlWriter.WriteEndElement()

			$xmlWriter.WriteEndElement()

			$xmlWriter.WriteEndDocument()

			$xmlWriter.Finalize
			$xmlWriter.Flush()
			$xmlWriter.Close()

		}
	}

}