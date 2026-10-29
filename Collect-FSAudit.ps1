<#
.SYNOPSIS
    File server permission audit - data collection. READ-ONLY.

.DESCRIPTION
    Collects, without changing anything on the file server or in AD:
      1. Folder tree under RootPath (folders only; files are only counted from the
         directory listing, never opened) with owner, inheritance flag and the full
         DACL (explicit + inherited ACEs, as Windows actually evaluates them).
      2. Active Directory users, groups, computers and direct group memberships.
      3. Local groups / users of this server (BUILTIN\Administrators, BUILTIN\Users ...).
      4. SMB shares and share-level permissions.
      5. Name resolution for every SID found in owners / ACEs.

    SAFETY
      - Uses only read operations: Get-* cmdlets, DirectoryInfo.Enumerate*,
        GetAccessControl (read), SecurityIdentifier.Translate, ADSI/LDAP reads.
      - Contains no calls that change ACLs, owners, attributes, or that move,
        rename or delete anything.
      - Files are never opened: only names and sizes from the directory listing.
      - Never takes ownership or bypasses denied access. Folders that cannot be
        read are just written to errors.csv.
      - Writes ONLY into OutputDir. OutputDir must be outside RootPath and must be
        empty or not exist (nothing is overwritten). The optional ZIP is created
        next to OutputDir and only if it does not exist yet.

.OUTPUT  (UTF-8 CSV files in OutputDir)
    folders.csv       one row per folder
                      Id, ParentId, Depth, Path, Name, OwnerSid, InheritanceDisabled,
                      AclCanonical, AclId, ExplicitAceCount, InheritedAceCount,
                      FileCount, FileBytes, SubfolderCount, IsReparsePoint,
                      LastWriteUtc, Error
    acl_entries.csv   unique ACLs (many folders share one AclId)
                      AclId, Order, Sid, AccessType, RightsMask, Rights,
                      InheritanceFlags, PropagationFlags, IsInherited
    acl_special.csv   AclId, Kind   (EMPTY_DACL / NULL_DACL)
    sids.csv          Sid, Name, Resolved
    ad_users.csv, ad_groups.csv, ad_computers.csv, ad_members.csv
    local_users.csv, local_groups.csv, local_members.csv
    shares.csv, share_access.csv
    errors.csv, run.log, meta.json

.EXAMPLE
    # Test run on a small subfolder first, without AD:
    .\Collect-FSAudit.ps1 -RootPath 'D:\Shares\Data\IT' -OutputDir 'C:\FSAudit\Test1' -SkipAD

.EXAMPLE
    # Full run:
    .\Collect-FSAudit.ps1 -RootPath 'D:\Shares\Data'

.EXAMPLE
    # Only AD (on a machine with RSAT, if the file server has no AD module):
    .\Collect-FSAudit.ps1 -SkipFolders -SkipLocal -SkipShares -OutputDir 'C:\FSAudit\AD'
#>

[CmdletBinding()]
param(
    [string]$RootPath,
    [string]$OutputDir = ('C:\FSAudit\Audit_' + (Get-Date -Format 'yyyyMMdd_HHmmss')),
    [switch]$SkipFolders,
    [switch]$SkipAD,
    [switch]$SkipLocal,
    [switch]$SkipShares,
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1'
$StartTime = Get-Date

# =====================================================================
# Helpers
# =====================================================================
function Get-FullPathSafe([string]$p) {
    $full = [System.IO.Path]::GetFullPath($p)
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

function Format-Date($d) {
    if ($null -eq $d) { return '' }
    try { return ([datetime]$d).ToString('o') } catch { return [string]$d }
}

function ConvertTo-LongPath([string]$p) {
    if ($p.StartsWith('\\?\')) { return $p }
    if ($p.StartsWith('\\'))   { return '\\?\UNC\' + $p.Substring(2) }
    return '\\?\' + $p
}

function ConvertFrom-LongPath([string]$p) {
    if ($p.StartsWith('\\?\UNC\')) { return '\\' + $p.Substring(8) }
    if ($p.StartsWith('\\?\'))     { return $p.Substring(4) }
    return $p
}

function Get-RightsMask($rights) {
    # FileSystemRights is Int32-based; generic rights (0x80000000 ...) are negative.
    return [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$rights), 0)
}

function Resolve-SidName([string]$sid) {
    try {
        $o = New-Object System.Security.Principal.SecurityIdentifier($sid)
        return $o.Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $null }
}

function Resolve-NameSid([string]$name) {
    try {
        $o = New-Object System.Security.Principal.NTAccount($name)
        return $o.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return '' }
}

# =====================================================================
# Safety checks on paths
# =====================================================================
if (-not $SkipFolders -and -not $RootPath) { throw "-RootPath is required (the folder to audit, e.g. -RootPath 'D:\Shares\Data'). Use -SkipFolders for an AD/shares-only run." }
$RootFull = ''
if ($RootPath) { $RootFull = Get-FullPathSafe $RootPath }
$OutFull  = Get-FullPathSafe $OutputDir

$rootCmp = $RootFull.TrimEnd('\') + '\'
$outCmp  = $OutFull.TrimEnd('\') + '\'
if ($RootFull -and ($outCmp.StartsWith($rootCmp, [System.StringComparison]::OrdinalIgnoreCase) -or
    $rootCmp.StartsWith($outCmp, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "OutputDir ($OutFull) must be outside RootPath ($RootFull)."
}

if (-not $SkipFolders -and -not [System.IO.Directory]::Exists($RootFull)) {
    throw "RootPath not found: $RootFull"
}

if ([System.IO.Directory]::Exists($OutFull)) {
    $firstEntry = [System.IO.Directory]::EnumerateFileSystemEntries($OutFull) | Select-Object -First 1
    if ($firstEntry) { throw "OutputDir is not empty: $OutFull. Use a new folder, nothing will be overwritten." }
} else {
    [void][System.IO.Directory]::CreateDirectory($OutFull)
}

$LogFile = Join-Path $OutFull 'run.log'
function Write-Log([string]$msg, [string]$level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level, $msg
    if ($level -eq 'ERROR') { Write-Host $line -ForegroundColor Red }
    elseif ($level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line }
    [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
}

function Save-Csv([System.Collections.IEnumerable]$Data, [string]$name) {
    # Copy into ArrayList explicitly: @() on a generic List passed into a function
    # throws "Argument types do not match" in PowerShell.
    $path = Join-Path $OutFull $name
    $buf = New-Object System.Collections.ArrayList
    if ($null -ne $Data) { foreach ($r in $Data) { [void]$buf.Add($r) } }
    $count = $buf.Count
    if ($count -gt 0) {
        $buf | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        [System.IO.File]::WriteAllText($path, '', [System.Text.Encoding]::UTF8)
    }
    Write-Log ("Saved {0} ({1} rows)" -f $name, $count)
}

$ErrorRows = New-Object System.Collections.Generic.List[object]
function Add-Err([string]$path, [string]$stage, [string]$msg) {
    $ErrorRows.Add([pscustomobject]@{ Path = $path; Stage = $stage; Message = $msg })
}

# =====================================================================
# Environment info
# =====================================================================
Write-Log "Collect-FSAudit v$ScriptVersion started"
Write-Log "RootPath  : $RootFull"
Write-Log "OutputDir : $OutFull"

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([System.Security.Principal.WindowsPrincipal]$me).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Log ("Running as {0}, elevated admin: {1}, PowerShell {2}" -f $me.Name, $isAdmin, $PSVersionTable.PSVersion)
if (-not $isAdmin) { Write-Log 'Not running elevated - many folders may be unreadable. Recommended: Run as Administrator.' 'WARN' }

$isDC = $false
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $isDC = ($cs.DomainRole -ge 4)
    Write-Log ("Computer {0}, domain {1}, DomainRole {2}" -f $cs.Name, $cs.Domain, $cs.DomainRole)
} catch { Write-Log "Win32_ComputerSystem query failed: $($_.Exception.Message)" 'WARN' }

$SidSet = New-Object 'System.Collections.Generic.HashSet[string]'
$Counts = [ordered]@{}

# =====================================================================
# 1. Folders + ACL
# =====================================================================
if (-not $SkipFolders) {
    try {
        Write-Log 'Folder scan started'

        $isCore = ($PSVersionTable.PSEdition -eq 'Core')
        $sections = [System.Security.AccessControl.AccessControlSections]'Access, Owner'
        $sidType  = [System.Security.Principal.SecurityIdentifier]

        function Get-DirAcl([System.IO.DirectoryInfo]$d) {
            if ($isCore) { return [System.IO.FileSystemAclExtensions]::GetAccessControl($d, $sections) }
            return $d.GetAccessControl($sections)
        }

        # Long path support check (\\?\ prefix). Works in PowerShell 7; in 5.1 depends on .NET settings.
        $UseLongPrefix = $false
        try {
            $t = New-Object System.IO.DirectoryInfo -ArgumentList (ConvertTo-LongPath $RootFull)
            if ($t.Exists) {
                $null = Get-DirAcl $t
                $null = $t.EnumerateDirectories() | Select-Object -First 1
                $UseLongPrefix = $true
            }
        } catch { $UseLongPrefix = $false }
        Write-Log ("Long path mode (\\?\ prefix): {0}" -f $UseLongPrefix)
        if (-not $UseLongPrefix) { Write-Log 'Paths over 260 chars may fail and will be listed in errors.csv. PowerShell 7 (pwsh) handles them.' 'WARN' }

        $FolderRows = New-Object System.Collections.Generic.List[object]
        $AclRows    = New-Object System.Collections.Generic.List[object]
        $AclSpecial = New-Object System.Collections.Generic.List[object]
        $AclMap     = New-Object 'System.Collections.Generic.Dictionary[string,int]'
        $Stack      = New-Object 'System.Collections.Generic.Stack[object]'

        $rootWork = $RootFull
        if ($UseLongPrefix) { $rootWork = ConvertTo-LongPath $RootFull }
        $rootIsReparse = $false
        try { $rootIsReparse = [bool]((New-Object System.IO.DirectoryInfo -ArgumentList $rootWork).Attributes -band [System.IO.FileAttributes]::ReparsePoint) } catch {}
        $Stack.Push(@{ Path = $rootWork; ParentId = 0; Depth = 0; IsReparse = $rootIsReparse })

        $id = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        while ($Stack.Count -gt 0) {
            $item = $Stack.Pop()
            $id++
            $workPath = [string]$item.Path
            $outPath  = ConvertFrom-LongPath $workPath

            $row = [ordered]@{
                Id                  = $id
                ParentId            = $item.ParentId
                Depth               = $item.Depth
                Path                = $outPath
                Name                = ''
                OwnerSid            = ''
                InheritanceDisabled = ''
                AclCanonical        = ''
                AclId               = ''
                ExplicitAceCount    = ''
                InheritedAceCount   = ''
                FileCount           = ''
                FileBytes           = ''
                SubfolderCount      = ''
                IsReparsePoint      = [bool]$item.IsReparse
                LastWriteUtc        = ''
                Error               = ''
            }
            $errs = New-Object System.Collections.Generic.List[string]

            $di = New-Object System.IO.DirectoryInfo -ArgumentList $workPath
            $row.Name = $di.Name
            if ($item.Depth -eq 0) { $row.Name = $outPath }
            try { $row.LastWriteUtc = $di.LastWriteTimeUtc.ToString('o') } catch {}

            # ---- ACL (read only) ----
            try {
                $sec = Get-DirAcl $di
                $owner = $sec.GetOwner($sidType)
                if ($owner) { $row.OwnerSid = $owner.Value; [void]$SidSet.Add($owner.Value) }
                $row.InheritanceDisabled = $sec.AreAccessRulesProtected
                $row.AclCanonical        = $sec.AreAccessRulesCanonical

                $rules = $sec.GetAccessRules($true, $true, $sidType)
                $parts = New-Object System.Collections.Generic.List[string]
                $nExp = 0; $nInh = 0
                foreach ($r in $rules) {
                    $sid = $r.IdentityReference.Value
                    [void]$SidSet.Add($sid)
                    if ($r.IsInherited) { $nInh++ } else { $nExp++ }
                    $parts.Add(('{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $sid, $r.AccessControlType, (Get-RightsMask $r.FileSystemRights), $r.InheritanceFlags, $r.PropagationFlags, $r.IsInherited, $r.FileSystemRights))
                }
                $row.ExplicitAceCount  = $nExp
                $row.InheritedAceCount = $nInh

                if ($parts.Count -eq 0) {
                    $sddl = $sec.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
                    if ($sddl -match 'NO_ACCESS_CONTROL') { $key = '<NULL_DACL>' } else { $key = '<EMPTY_DACL>' }
                } else {
                    $key = $parts -join ';'
                }

                $aclId = 0
                if (-not $AclMap.TryGetValue($key, [ref]$aclId)) {
                    $aclId = $AclMap.Count + 1
                    $AclMap.Add($key, $aclId)
                    if ($key.StartsWith('<')) {
                        $AclSpecial.Add([pscustomobject]@{ AclId = $aclId; Kind = $key.Trim('<', '>') })
                    } else {
                        $order = 0
                        foreach ($p in $parts) {
                            $order++
                            $f = $p.Split('|')
                            $AclRows.Add([pscustomobject]@{
                                AclId            = $aclId
                                Order            = $order
                                Sid              = $f[0]
                                AccessType       = $f[1]
                                RightsMask       = $f[2]
                                Rights           = $f[6]
                                InheritanceFlags = $f[3]
                                PropagationFlags = $f[4]
                                IsInherited      = $f[5]
                            })
                        }
                    }
                }
                $row.AclId = $aclId
            } catch {
                $errs.Add("ACL: $($_.Exception.Message)")
                Add-Err $outPath 'ACL' $_.Exception.Message
            }

            # ---- Contents (listing only, files are not opened) ----
            if (-not $item.IsReparse) {
                try {
                    $fc = 0; [int64]$fb = 0
                    foreach ($f in $di.EnumerateFiles()) { $fc++; $fb += $f.Length }
                    $row.FileCount = $fc
                    $row.FileBytes = $fb
                } catch {
                    $errs.Add("Files: $($_.Exception.Message)")
                    Add-Err $outPath 'ListFiles' $_.Exception.Message
                }
                try {
                    $sc = 0
                    foreach ($d in $di.EnumerateDirectories()) {
                        $sc++
                        $rp = [bool]($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
                        $Stack.Push(@{ Path = $d.FullName; ParentId = $id; Depth = $item.Depth + 1; IsReparse = $rp })
                    }
                    $row.SubfolderCount = $sc
                } catch {
                    $errs.Add("Dirs: $($_.Exception.Message)")
                    Add-Err $outPath 'ListDirs' $_.Exception.Message
                }
            }

            if ($errs.Count -gt 0) { $row.Error = ($errs -join ' || ') }
            $FolderRows.Add([pscustomobject]$row)

            if (($id % 500) -eq 0) {
                $rate = [math]::Round($id / [math]::Max($sw.Elapsed.TotalSeconds, 1), 1)
                Write-Progress -Activity 'Scanning folders (read-only)' -Status ("{0} folders, {1} queued, {2}/s, {3} unique ACLs, {4} errors" -f $id, $Stack.Count, $rate, $AclMap.Count, $ErrorRows.Count) -CurrentOperation $outPath
            }
            if (($id % 10000) -eq 0) { Write-Log ("... {0} folders scanned" -f $id) }
        }
        Write-Progress -Activity 'Scanning folders (read-only)' -Completed
        Write-Log ("Folder scan done: {0} folders, {1} unique ACLs, {2:N0} s" -f $id, $AclMap.Count, $sw.Elapsed.TotalSeconds)

        Save-Csv $FolderRows 'folders.csv'
        Save-Csv $AclRows    'acl_entries.csv'
        Save-Csv $AclSpecial 'acl_special.csv'
        $Counts['Folders']    = $FolderRows.Count
        $Counts['UniqueAcls'] = $AclMap.Count
        $Counts['LongPathMode'] = $UseLongPrefix
    } catch {
        Write-Log "Folder scan failed: $($_.Exception.Message) [line $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR'
        Add-Err $RootFull 'FolderScan' $_.Exception.Message
    }
}

# =====================================================================
# 2. Local groups / users of this server
# =====================================================================
if (-not $SkipLocal) {
    if ($isDC) {
        Write-Log 'This server is a domain controller - no local SAM, BUILTIN groups come from AD.'
    } else {
        try {
            $LocalUsers = foreach ($u in Get-LocalUser) {
                [void]$SidSet.Add($u.SID.Value)
                [pscustomobject]@{ Sid = $u.SID.Value; Name = $u.Name; Enabled = $u.Enabled; LastLogon = Format-Date $u.LastLogon; Description = $u.Description }
            }
            $LocalGroups  = New-Object System.Collections.Generic.List[object]
            $LocalMembers = New-Object System.Collections.Generic.List[object]
            foreach ($g in Get-LocalGroup) {
                $LocalGroups.Add([pscustomobject]@{ Sid = $g.SID.Value; Name = $g.Name; Description = $g.Description })
                # ADSI read is used instead of Get-LocalGroupMember (that one fails on orphaned SIDs)
                try {
                    $adsiGroup = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $g.Name)
                    foreach ($m in @($adsiGroup.Invoke('Members'))) {
                        $mt = $m.GetType()
                        $sidBytes = $mt.InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                        $adsPath  = $mt.InvokeMember('ADsPath',   'GetProperty', $null, $m, $null)
                        $cls      = $mt.InvokeMember('Class',     'GetProperty', $null, $m, $null)
                        $msid = ''
                        if ($sidBytes) { $msid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value }
                        $LocalMembers.Add([pscustomobject]@{
                            GroupSid   = $g.SID.Value
                            GroupName  = $g.Name
                            MemberSid  = $msid
                            MemberName = (Resolve-SidName $msid)
                            MemberClass= $cls
                            AdsPath    = $adsPath
                        })
                    }
                } catch {
                    Add-Err $g.Name 'LocalGroupMembers' $_.Exception.Message
                    Write-Log "Local group $($g.Name): $($_.Exception.Message)" 'WARN'
                }
            }
            Save-Csv $LocalUsers   'local_users.csv'
            Save-Csv $LocalGroups  'local_groups.csv'
            Save-Csv $LocalMembers 'local_members.csv'
        } catch {
            Write-Log "Local groups failed: $($_.Exception.Message) [line $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR'
            Add-Err '' 'Local' $_.Exception.Message
        }
    }
}

# =====================================================================
# 3. SMB shares
# =====================================================================
if (-not $SkipShares) {
    try {
        $Shares = New-Object System.Collections.Generic.List[object]
        $ShareAccess = New-Object System.Collections.Generic.List[object]
        foreach ($s in Get-SmbShare) {
            $Shares.Add([pscustomobject]@{
                Name                  = $s.Name
                ScopeName             = $s.ScopeName
                Path                  = $s.Path
                Description           = $s.Description
                Special               = $s.Special
                ShareType             = [string]$s.ShareType
                FolderEnumerationMode = [string]$s.FolderEnumerationMode
                CachingMode           = [string]$s.CachingMode
                EncryptData           = $s.EncryptData
                CurrentUsers          = $s.CurrentUsers
            })
            try {
                foreach ($a in Get-SmbShareAccess -Name $s.Name -ScopeName $s.ScopeName) {
                    $ShareAccess.Add([pscustomobject]@{
                        ShareName         = $a.Name
                        ScopeName         = $a.ScopeName
                        AccountName       = $a.AccountName
                        Sid               = (Resolve-NameSid $a.AccountName)
                        AccessControlType = [string]$a.AccessControlType
                        AccessRight       = [string]$a.AccessRight
                    })
                }
            } catch { Add-Err $s.Name 'ShareAccess' $_.Exception.Message }
        }
        Save-Csv $Shares 'shares.csv'
        Save-Csv $ShareAccess 'share_access.csv'
        $Counts['Shares'] = $Shares.Count
    } catch {
        Write-Log "Shares failed: $($_.Exception.Message) [line $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR'
        Add-Err '' 'Shares' $_.Exception.Message
    }
}

# =====================================================================
# 4. Active Directory (read only)
# =====================================================================
if (-not $SkipAD) {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'ActiveDirectory module (RSAT) is not installed here. Run again on a machine with RSAT: -SkipFolders -SkipLocal -SkipShares'
        }
        Import-Module ActiveDirectory
        Write-Log 'AD export started'

        $domain = Get-ADDomain
        $domSid = $domain.DomainSID.Value
        $DnMap  = @{}   # DN -> object info (case-insensitive)

        # Users
        $adUsers = @(Get-ADUser -Filter * -Properties DisplayName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AccountExpirationDate, whenCreated, PrimaryGroupID, Department, Title, Description, mail, userPrincipalName, Manager)
        $UserRows = foreach ($u in $adUsers) {
            $DnMap[$u.DistinguishedName] = @{ Sid = $u.SID.Value; Name = $u.SamAccountName; Type = 'user' }
            [pscustomobject]@{
                Sid                   = $u.SID.Value
                SamAccountName        = $u.SamAccountName
                UserPrincipalName     = $u.UserPrincipalName
                DisplayName           = $u.DisplayName
                Enabled               = $u.Enabled
                LastLogonDate         = Format-Date $u.LastLogonDate
                PasswordLastSet       = Format-Date $u.PasswordLastSet
                PasswordNeverExpires  = $u.PasswordNeverExpires
                AccountExpirationDate = Format-Date $u.AccountExpirationDate
                WhenCreated           = Format-Date $u.whenCreated
                Department            = $u.Department
                Title                 = $u.Title
                Description           = $u.Description
                Mail                  = $u.mail
                Manager               = $u.Manager
                PrimaryGroupSid       = "$domSid-$($u.PrimaryGroupID)"
                DistinguishedName     = $u.DistinguishedName
            }
        }

        # Computers (needed to resolve group members)
        $adComputers = @(Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, LastLogonDate, PrimaryGroupID)
        $CompRows = foreach ($c in $adComputers) {
            $DnMap[$c.DistinguishedName] = @{ Sid = $c.SID.Value; Name = $c.SamAccountName; Type = 'computer' }
            [pscustomobject]@{
                Sid               = $c.SID.Value
                SamAccountName    = $c.SamAccountName
                Enabled           = $c.Enabled
                OperatingSystem   = $c.OperatingSystem
                LastLogonDate     = Format-Date $c.LastLogonDate
                PrimaryGroupSid   = "$domSid-$($c.PrimaryGroupID)"
                DistinguishedName = $c.DistinguishedName
            }
        }

        # Groups
        $adGroups = @(Get-ADGroup -Filter * -Properties member, Description, ManagedBy, whenCreated, mail)
        $GroupBySid = @{}
        $GroupRows = foreach ($g in $adGroups) {
            $DnMap[$g.DistinguishedName] = @{ Sid = $g.SID.Value; Name = $g.SamAccountName; Type = 'group' }
            $GroupBySid[$g.SID.Value] = $g.SamAccountName
            [pscustomobject]@{
                Sid               = $g.SID.Value
                SamAccountName    = $g.SamAccountName
                Name              = $g.Name
                GroupScope        = [string]$g.GroupScope
                GroupCategory     = [string]$g.GroupCategory
                Description       = $g.Description
                ManagedBy         = $g.ManagedBy
                Mail              = $g.mail
                WhenCreated       = Format-Date $g.whenCreated
                DirectMemberCount = @($g.member).Count
                DistinguishedName = $g.DistinguishedName
            }
        }

        # Direct memberships
        $MemberRows = New-Object System.Collections.Generic.List[object]
        foreach ($g in $adGroups) {
            foreach ($mdn in @($g.member)) {
                if (-not $mdn) { continue }
                if (-not $DnMap.ContainsKey($mdn)) {
                    # Foreign security principals, gMSA, contacts etc.
                    try {
                        $o = Get-ADObject -Identity $mdn -Properties objectSid, objectClass, sAMAccountName
                        $osid = ''
                        if ($o.objectSid) { $osid = $o.objectSid.Value }
                        $oname = $o.sAMAccountName
                        if (-not $oname -and $osid) { $oname = Resolve-SidName $osid }
                        if (-not $oname) { $oname = $o.Name }
                        $DnMap[$mdn] = @{ Sid = $osid; Name = $oname; Type = [string]$o.objectClass }
                    } catch {
                        $DnMap[$mdn] = @{ Sid = ''; Name = ''; Type = 'unresolved' }
                        Add-Err $mdn 'ADMemberResolve' $_.Exception.Message
                    }
                }
                $m = $DnMap[$mdn]
                $MemberRows.Add([pscustomobject]@{
                    GroupSid   = $g.SID.Value
                    GroupName  = $g.SamAccountName
                    MemberSid  = $m.Sid
                    MemberName = $m.Name
                    MemberType = $m.Type
                    MemberDN   = $mdn
                    Source     = 'member'
                })
            }
        }
        # Primary group (e.g. Domain Users) is not stored in 'member'
        foreach ($u in $UserRows) {
            $MemberRows.Add([pscustomobject]@{
                GroupSid = $u.PrimaryGroupSid; GroupName = $GroupBySid[$u.PrimaryGroupSid]
                MemberSid = $u.Sid; MemberName = $u.SamAccountName; MemberType = 'user'
                MemberDN = $u.DistinguishedName; Source = 'primaryGroup'
            })
        }
        foreach ($c in $CompRows) {
            $MemberRows.Add([pscustomobject]@{
                GroupSid = $c.PrimaryGroupSid; GroupName = $GroupBySid[$c.PrimaryGroupSid]
                MemberSid = $c.Sid; MemberName = $c.SamAccountName; MemberType = 'computer'
                MemberDN = $c.DistinguishedName; Source = 'primaryGroup'
            })
        }

        Save-Csv $UserRows   'ad_users.csv'
        Save-Csv $GroupRows  'ad_groups.csv'
        Save-Csv $CompRows   'ad_computers.csv'
        Save-Csv $MemberRows 'ad_members.csv'
        $Counts['AdUsers']   = @($UserRows).Count
        $Counts['AdGroups']  = @($GroupRows).Count
        $Counts['AdMembers'] = $MemberRows.Count
        $Counts['DomainSid'] = $domSid
        $Counts['Domain']    = $domain.DNSRoot
    } catch {
        Write-Log "AD export failed: $($_.Exception.Message) [line $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR'
        Add-Err '' 'AD' $_.Exception.Message
    }
}

# =====================================================================
# 5. Resolve every SID seen in ACLs / owners
# =====================================================================
if ($SidSet.Count -gt 0) {
    $SidRows = foreach ($s in $SidSet) {
        $n = Resolve-SidName $s
        [pscustomobject]@{ Sid = $s; Name = $n; Resolved = [bool]$n }
    }
    Save-Csv $SidRows 'sids.csv'
    $Counts['Sids'] = $SidSet.Count
    $Counts['UnresolvedSids'] = @($SidRows | Where-Object { -not $_.Resolved }).Count
}

# =====================================================================
# Finish
# =====================================================================
Save-Csv $ErrorRows 'errors.csv'
$Counts['Errors'] = $ErrorRows.Count

$meta = [ordered]@{
    ScriptVersion    = $ScriptVersion
    Computer         = $env:COMPUTERNAME
    RunAs            = $me.Name
    Elevated         = $isAdmin
    IsDomainController = $isDC
    PowerShell       = [string]$PSVersionTable.PSVersion
    RootPath         = $RootFull
    StartUtc         = $StartTime.ToUniversalTime().ToString('o')
    EndUtc           = (Get-Date).ToUniversalTime().ToString('o')
    Skipped          = @{ Folders = [bool]$SkipFolders; AD = [bool]$SkipAD; Local = [bool]$SkipLocal; Shares = [bool]$SkipShares }
    Counts           = $Counts
}
[System.IO.File]::WriteAllText((Join-Path $OutFull 'meta.json'), ($meta | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)

Write-Log ("Finished in {0:N0} s. Errors: {1}" -f ((Get-Date) - $StartTime).TotalSeconds, $ErrorRows.Count)

if (-not $NoZip) {
    $zip = $OutFull + '.zip'
    if (Test-Path -LiteralPath $zip) {
        Write-Log "ZIP not created, file already exists: $zip" 'WARN'
    } else {
        try {
            Compress-Archive -Path (Join-Path $OutFull '*') -DestinationPath $zip
            Write-Host "ZIP: $zip"
        } catch { Write-Log "ZIP failed: $($_.Exception.Message)" 'WARN' }
    }
}
Write-Host "Output: $OutFull"
