<#
.SYNOPSIS
    Step 2 (optional) - turns an OU or a group from Active Directory into KnownAdmins entries for the settings file.

.DESCRIPTION
    Run from the management computer with an account that can read Active Directory. Give it what Active Directory Users and
    Computers shows: the canonical name of an OU (every security group directly in it; -Recurse adds the sub-OUs), of a group or of a
    user, or a distinguished name. Several -Path values are allowed.
    Only a group that holds write access on a folder under C:\Windows, Program Files or an ExtraAllowedPaths entry, and is not in
    Administrators, needs an entry (README, section 11: what the setting is for, who is affected). Permissions name groups, not people.
    Without -Update nothing is written: the KnownAdmins line is printed, ready to paste. -Update merges the entries into the settings
    file (-Replace discards the existing ones) after a backup to Outputs\<profile>\settings-backups and a Y/N prompt; the new text is
    proven to load before the file is touched; -WhatIf shows the change without making it.
    It refuses the whole domain and every group that must never count as an administrator (Domain Users, Authenticated Users, ...).
    It skips what already counts (Administrators, Domain Admins, Enterprise Admins, Server / Print / Backup Operators), distribution
    groups (they cannot hold permissions) and user accounts (reported with the groups they belong to). The new value applies at the next
    build (1_AL_build_policy.ps1, then 2_AL_create_gpos.ps1). Nothing on a server changes here.

.PARAMETER Path
    One or more canonical names (contoso.com/Top OU/Sub OU/Name, as ADUC shows them) or distinguished names (OU=...,DC=...) of an OU,
    a container, a group or a user. A slash inside a name is written \/ in a canonical name. Aliases: -CanonicalName, -DistinguishedName.

.PARAMETER SettingsFile
    Settings file to read and, with -Update, to write. Default: AL-Settings.psd1 next to the script.

.PARAMETER Recurse
    For an OU: include the groups (and users) in its sub-OUs. Default: only what is directly in the OU.

.PARAMETER IncludeUsers
    Also list user accounts as entries. Normally not needed: permissions name groups. Use it only for a permission that names a person.

.PARAMETER AsSid
    Write SIDs instead of DOMAIN\Name. A name the settings check refuses, or a non-ASCII name, falls back to its SID anyway.

.PARAMETER Update
    Write the result into the settings file (merged with the existing entries) after a backup and a Y/N prompt. Without -Update the
    line is only printed.

.PARAMETER Replace
    With -Update: discard the existing entries instead of merging with them.

.PARAMETER NoConfirm
    Skip the yellow Y/N prompt (automation). A non-interactive session without -NoConfirm stops before the file is written.

.PARAMETER WhatIf
    With -Update: show the change that would be written without touching the settings file.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: one row per principal found (OK = entry, INFO = already an administrator or a user not listed,
    WARN = distribution group), the KnownAdmins line ready to paste, and with -Update the backup path and the SHA-256 before and after.
    Rows as CSV in Logs\0_AL_known_admins-<timestamp>.csv; transcript in Logs\0_AL_known_admins-<timestamp>.log. Exit code 1 on a STOP.

.EXAMPLE
    .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-User-Accounts/DA'
    Survey of an OU of administrator accounts: prints each account with the groups it belongs to and lists nothing. Writes nothing.

.EXAMPLE
    .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups'
    Prints the KnownAdmins line for every security group directly in that OU. Writes nothing.

.EXAMPLE
    .\0_AL_known_admins.ps1 -Path 'contoso.com/Tier 0/Groups/Tier0-Server-Admins' -Update
    Adds one group to the settings file after a backup and a Y/N prompt.

.EXAMPLE
    .\0_AL_known_admins.ps1 -Path 'OU=Admin-Groups,OU=Tier 0,DC=contoso,DC=com' -Recurse -Update -NoConfirm
    Every security group in that OU tree, written without a prompt (automation).

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT ActiveDirectory module; read access to Active Directory.
    Changes  : only the settings file, only with -Update (backup first). Nothing on a server.
    Undo     : copy the backup from Outputs\<profile>\settings-backups over the settings file, or edit the KnownAdmins line.
    README   : section 11 (who counts as an administrator; what KnownAdmins is for).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][Alias('CanonicalName', 'DistinguishedName')][ValidateNotNullOrEmpty()][string[]]$Path,
    [string]$SettingsFile,
    [switch]$Recurse,
    [switch]$IncludeUsers,
    [switch]$AsSid,
    [switch]$Update,
    [switch]$Replace,
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_known_admins' -SettingsFile $SettingsFile
$R = New-ALResults
$Domains = @{}

# A domain by DNS name (this computer's own or another one in the forest): PDC emulator, NetBIOS name, DN, and the DNs of the direct
# members of its Administrators group
function Get-ALDomainFor([string]$Dns) {
    $KeyName = $Dns.ToLowerInvariant()
    if ($Domains.ContainsKey($KeyName)) { return $Domains[$KeyName] }
    try { $D = Get-ADDomain -Identity $Dns -ErrorAction Stop }
    catch { throw "STOP: domain '$Dns' could not be read ($($_.Exception.Message)). A canonical name starts with the DNS name of a domain in this forest, as Active Directory Users and Computers shows it." }
    $Admins = @()
    try { $Admins = @((Get-ADGroup -Identity 'S-1-5-32-544' -Properties member -Server $D.PDCEmulator -ErrorAction Stop).member) } catch { }
    $Info = [pscustomobject]@{ DnsRoot = $D.DNSRoot; DN = $D.DistinguishedName; PDC = $D.PDCEmulator; NetBIOS = $D.NetBIOSName; Admins = $Admins }
    $Domains[$KeyName] = $Info
    return $Info
}

# One -Path value -> the object it names (OU, container, group or user) and its domain. A canonical name is walked one level at a
# time (name = segment), so OU= and CN= never have to be guessed.
function Resolve-ALPath([string]$P) {
    if ($P -match '^(CN|OU)=') {
        $Dns = (@([regex]::Matches($P, '(?:^|,)\s*DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.')
        $Dom = Get-ALDomainFor $Dns
        try { $Obj = Get-ADObject -Identity $P -Properties objectClass, canonicalName -Server $Dom.PDC -ErrorAction Stop }
        catch { throw "STOP: '$P' was not found in $($Dom.DnsRoot) ($($_.Exception.Message))." }
    }
    else {
        $Cn = Split-ALCanonicalName $P
        $Dom = Get-ALDomainFor $Cn.Domain
        if (-not @($Cn.Segments).Count) { throw "STOP: '$P' is a whole domain. Give an OU or a group, e.g. $($Dom.DnsRoot)/Admin Groups." }
        $Base = $Dom.DN; $Obj = $null
        foreach ($Seg in $Cn.Segments) {
            $Hits = @(Get-ADObject -SearchBase $Base -SearchScope OneLevel -LDAPFilter "(name=$(ConvertTo-ALLdapFilterValue $Seg))" -Properties objectClass, canonicalName -Server $Dom.PDC -ErrorAction Stop)
            if ($Hits.Count -eq 0) { throw "STOP: '$Seg' was not found under $Base (from '$P'). Check the name in Active Directory Users and Computers." }
            if ($Hits.Count -gt 1) { throw "STOP: '$Seg' names $($Hits.Count) objects under $Base (from '$P'). Use the distinguished name instead." }
            $Obj = $Hits[0]; $Base = $Obj.DistinguishedName
        }
    }
    if ($Obj.ObjectClass -eq 'domainDNS') { throw "STOP: '$P' is a whole domain. Give an OU or a group." }
    if ($Obj.ObjectClass -notin 'organizationalUnit', 'container', 'group', 'user') { throw "STOP: '$P' is a $($Obj.ObjectClass), not an OU, a group or a user." }
    return [pscustomobject]@{ Input = $P; Object = $Obj; Domain = $Dom }
}

# The groups and users a resolved -Path value stands for (a group or user itself; an OU: what is directly in it, -Recurse: the subtree)
function Get-ALPrincipalsOf($Hit) {
    $GroupProps = 'objectSid', 'sAMAccountName', 'msDS-PrincipalName', 'canonicalName', 'memberOf', 'groupType'
    $UserProps = 'objectSid', 'sAMAccountName', 'msDS-PrincipalName', 'canonicalName', 'memberOf'
    $O = $Hit.Object; $Server = $Hit.Domain.PDC
    if ($O.ObjectClass -eq 'group') { return @(Get-ADGroup -Identity $O.DistinguishedName -Properties $GroupProps -Server $Server -ErrorAction Stop) }
    if ($O.ObjectClass -eq 'user') { return @(Get-ADUser -Identity $O.DistinguishedName -Properties $UserProps -Server $Server -ErrorAction Stop) }
    $Scope = if ($Recurse) { 'Subtree' } else { 'OneLevel' }
    $List = @(Get-ADGroup -SearchBase $O.DistinguishedName -SearchScope $Scope -Filter * -Properties $GroupProps -Server $Server -ErrorAction Stop)
    $List += @(Get-ADUser -SearchBase $O.DistinguishedName -SearchScope $Scope -Filter * -Properties $UserProps -Server $Server -ErrorAction Stop)
    return $List
}

try {
    Import-ALModule ActiveDirectory
    $Entries = New-Object System.Collections.Generic.List[string]
    $UsersSeen = 0
    foreach ($P in $Path) {
        $Hit = Resolve-ALPath $P
        $O = $Hit.Object
        Write-Host "$P -> $($O.ObjectClass) $($O.DistinguishedName)"
        $Found = @(Get-ALPrincipalsOf $Hit)
        if (-not $Found.Count) { Add-ALResult $R 'WARN' 'Nothing found' "$($O.canonicalName) holds no group or user$(if (-not $Recurse) { ' (sub-OUs are not searched without -Recurse)' })."; continue }
        foreach ($Pr in @($Found | Sort-Object ObjectClass, Name)) {
            $Sid = "$($Pr.SID.Value)"
            $Name = "$($Pr.'msDS-PrincipalName')"
            if (-not $Name) { $Name = "$($Hit.Domain.NetBIOS)\$($Pr.SamAccountName)" }
            $Where = "$($Pr.canonicalName)"
            if ((Test-ALNeverAdmin $Sid) -or (Test-ALNeverAdmin $Name)) {
                throw "STOP: $Name ($Sid) at $Where is not an administrators group. Listing it would make every folder its members can write count as administrators-only and WIDEN the policy. Give an OU that holds only administrators groups. Nothing was written."
            }
            $Groups = @($Pr.memberOf | ForEach-Object { ("$_" -split '(?<!\\),')[0] -replace '^CN=', '' })
            if ($Pr.ObjectClass -eq 'user') {
                $UsersSeen++
                if (-not $IncludeUsers) { Add-ALResult $R 'INFO' 'User not listed' "$Name at $Where - KnownAdmins is for groups (direct member of: $(if ($Groups.Count) { $Groups -join ', ' } else { 'no group' })). -IncludeUsers lists it anyway."; continue }
            }
            elseif (([int64]$Pr.groupType -band 0x80000000) -eq 0) {
                Add-ALResult $R 'WARN' 'Distribution group' "$Name at $Where cannot hold permissions - not listed. Make it a security group if it is an administrators group."; continue
            }
            if (Test-ALBuiltInAdminSid $Sid) { Add-ALResult $R 'INFO' 'Already an administrator' "$Name ($Sid) at $Where - the scan and the C:\Admin check already treat it as one; not listed."; continue }
            $Entry = Get-ALKnownAdminEntry $Name $Sid -AsSid:$AsSid
            $Note = if ($Pr.DistinguishedName -in $Hit.Domain.Admins) { ' - direct member of Administrators' } else { '' }
            if ($Entry -ne $Name -and -not $AsSid) { $Note += ' - written as SID (the name has a character the settings refuse)' }
            if ($Entries -notcontains $Entry) { $Entries.Add($Entry) }
            Add-ALResult $R 'OK' 'KnownAdmins entry' "$Entry  <-  $Name ($Sid) at $Where$Note"
        }
    }

    $Existing = @($Cfg.KnownAdmins | Where-Object { $_ } | ForEach-Object { "$_" })
    # @( ) around the if: an empty array that leaves an if-expression becomes $null
    $Final = @(if ($Replace) { $Entries } else { @($Existing) + @($Entries | Where-Object { $E = $_; -not @($Existing | Where-Object { $_ -eq $E }).Count }) })
    $Line = 'KnownAdmins       = ' + (ConvertTo-ALArrayLiteral $Final)
    Write-Host ''
    if (-not $Entries.Count) { Write-Host "Nothing to list: no security group under the given path(s) needs a KnownAdmins entry$(if ($UsersSeen) { " ($UsersSeen user account(s) found - KnownAdmins takes groups; see the rows below)" })." -ForegroundColor Yellow }
    Write-Host "KnownAdmins line for $($Cfg.SettingsFile):"
    Write-Host "    $Line" -ForegroundColor Cyan
    if ($Update) {
        $Same = ((@($Final | Sort-Object) -join '|') -eq (@($Existing | Sort-Object) -join '|'))
        if ($Same) {
            Write-Host 'KnownAdmins is already current - nothing to change.' -ForegroundColor Green
            Add-ALResult $R 'OK' 'Settings' "unchanged: KnownAdmins = $(ConvertTo-ALArrayLiteral $Existing)"
        }
        else {
            $BackupFolder = Join-Path $Cfg.OutRoot 'settings-backups'
            if (-not $WhatIfPreference) {
                Confirm-ALChange -NoConfirm:$NoConfirm -Action "set KnownAdmins in $($Cfg.SettingsFile)" -Detail @(
                    "Now: $(ConvertTo-ALArrayLiteral $Existing)",
                    "New: $(ConvertTo-ALArrayLiteral $Final)",
                    'Effect: write access held by these groups no longer counts as user-writable in the AaronLocker scan and the C:\Admin check, so folders only they can change stay allowed for every account. Nothing changes on a server until the next 1_AL_build_policy.ps1 + 2_AL_create_gpos.ps1.',
                    "Undo: copy the backup from $BackupFolder over the settings file, or edit the KnownAdmins line.")
                $ConfirmPreference = 'None'
            }
            if ($PSCmdlet.ShouldProcess($Cfg.SettingsFile, "set KnownAdmins = $(ConvertTo-ALArrayLiteral $Final)")) {
                $W = Set-ALSettingsArray -SettingsFile $Cfg.SettingsFile -Key 'KnownAdmins' -Values $Final -BackupFolder $BackupFolder
                Add-ALResult $R 'OK' 'Settings updated' "KnownAdmins = $(ConvertTo-ALArrayLiteral $Final); backup $($W.Backup); SHA-256 $($W.Before) -> $($W.After)"
                Write-Host "Updated $($Cfg.SettingsFile) (backup: $($W.Backup)). It applies at the next 1_AL_build_policy.ps1 run." -ForegroundColor Green
            }
        }
    }
    elseif ($Entries.Count) { Write-Host 'Paste the line into the settings file, or run again with -Update to write it (asks Y/N).' }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'KnownAdmins'
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
