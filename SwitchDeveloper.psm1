$SolrPath = "$($PSScriptRoot)\solr"
$RegistryLoopbackPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\"
$RegistryLoopbackProperty = "DisableLoopbackCheck"

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
    }

    process
    {
        if (!(Test-Path -Path $RegistryLoopbackPath))
        {
            New-Item -Path $RegistryLoopbackPath | Out-Null
        }

        $RegistryLoopbackFullPath = Join-Path -Path $RegistryLoopbackPath -ChildPath $RegistryLoopbackProperty

        if (Test-Path -Path $RegistryLoopbackFullPath)
        {
            Set-ItemProperty -Path $RegistryLoopbackPath -Name $RegistryLoopbackProperty -Value $LoopbackValue -Type DWORD
        }
        else
        {
            New-ItemProperty -Path $RegistryLoopbackPath -Name $RegistryLoopbackProperty -Value $LoopbackValue -PropertyType DWORD
        }
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

# Sitecore Configuration Methods

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

        $SplitOptions = [System.StringSplitOptions]::RemoveEmptyEntries

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