<#
.SYNOPSIS
    Version 1.1.0.0
    Запускает очистку ACL папок с параметрами, заданными в начале файла.

.DESCRIPTION
    Значения параметров можно изменить непосредственно в блоке param(). При обычном
    запуске файла функция очистки вызывается автоматически. При точечном подключении
    файла функция только загружается в текущий сеанс и автоматическая очистка
    не запускается.

.PARAMETER Path
    Корневые папки, начиная с которых требуется выполнить очистку ACL.

.PARAMETER ExcludeFolderName
    Имена папок, исключаемых вместе со всем поддеревом.

.PARAMETER ExecutionMode
    Режим WhatIf только показывает план. Режим Apply разрешает изменение ACL.

.PARAMETER ConfirmChanges
    Определяет, требуется ли подтверждать каждое изменение в режиме Apply.

.PARAMETER UseAdsiCredential
    Включает проверку доменных и локальных учетных записей через ADSI WinNT с явно
    запрошенными учетными данными. При ошибке используется LookupAccountSid.

.PARAMETER AdsiAccountName
    Имя учетной записи для окна Get-Credential. Пустое значение позволяет указать
    имя непосредственно в окне запроса.

.PARAMETER RefreshStaleInheritance
    Включает принудительное обновление наследования для папок, где остались
    унаследованные правила пользователей или осиротевших SID.

.EXAMPLE
    .\Clear-FolderGroupAcl.ps1

Запускает скрипт со значениями, указанными в блоке param().

.EXAMPLE
    .\Clear-FolderGroupAcl.ps1 -ExecutionMode WhatIf

Принудительно запускает предварительную проверку без изменения ACL.

.EXAMPLE
    .\Clear-FolderGroupAcl.ps1 -Path 'D:\example1\example2\example3' `
        -ExcludeFolderName 'Archive' -ExecutionMode Apply

    Переопределяет значения блока param() при необходимости разового запуска.

.NOTES
    Перед первым применением оставьте ExecutionMode равным WhatIf и проверьте
    свойства PlannedRules в возвращаемых объектах.

    COPYRIGHT:
	    - Автор: t3hc0nnect10n
	    - Лицензия: CC BY-NC 4.0
	    - (c) 2026 t3hc0nnect10n
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    # Укажите одну или несколько корневых папок для обработки.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path = @(
        'D:\SharedFolder\Department\Root'
    )
    ,

    # Укажите точные имена исключаемых папок без путей.
    [Parameter()]
    [ValidateNotNull()]
    [ValidatePattern('^[^\\/:*?"<>|]+$')]
    [string[]]$ExcludeFolderName = @(
        'Example-1',
        'Example-2'
    )
    ,

    # Для реального изменения ACL замените WhatIf на Apply.
    [Parameter()]
    [ValidateSet('WhatIf', 'Apply')]
    [string]$ExecutionMode = 'WhatIf'
    ,

    # В режиме Apply значение $true запрашивает подтверждение изменений.
    [Parameter()]
    [bool]$ConfirmChanges = $true
    ,

    # Значение $true включает запрос учетных данных и проверку через ADSI WinNT.
    [Parameter()]
    [bool]$UseAdsiCredential = $true
    ,

    # Можно указать имя вида DOMAIN\User или оставить пустую строку.
    [Parameter()]
    [AllowEmptyString()]
    [string]$AdsiAccountName = 'DOMAIN\User'
    ,

    # Обновлять наследование, если нежелательная унаследованная ACE осталась
    # после очистки родительских папок.
    [Parameter()]
    [bool]$RefreshStaleInheritance = $true
    ,
    
    # Директория куда сохранится лог.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]$logDirectory = "C:\Users\$($env:USERNAME)\Downloads"
)

Set-StrictMode -Version Latest

# |====================================================|
# |   Структура функций Clear-FolderGroupAcl           |
# |====================================================|
# |                                                    |
# | Классификация учетных записей:                     |
# | - Get-WindowsPrincipalType                         |
# | - Get-AdsiPrincipalType                            |
# | - Get-AclPrincipalClassification                   |
# |                                                    |
# | Формирование объектов результата:                  |
# | - ConvertTo-FolderAclRuleInfo                      |
# | - ConvertTo-FolderAclCleanupResult                 |
# |                                                    |
# | Обновление наследования:                           |
# | - Invoke-FolderAclInheritanceRefresh               |
# |                                                    |
# | Журналирование:                                    |
# | - Write-FolderAclResultLog                         |
# |                                                    |
# | Обход и очистка ACL:                               |
# | - Clear-FolderGroupAcl                             |
# |                                                    |
# |====================================================|

# Блок подготовки Windows API. Тип добавляется один раз за сеанс PowerShell и
# предоставляет доступ к LookupAccountSid из advapi32.dll без внешних модулей.
if ($null -eq ('FolderAclNative.NativeMethods' -as [type])) {
    $nativeTypeDefinition = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FolderAclNative
{
    public enum SidNameUse
    {
        User = 1,
        Group = 2,
        Domain = 3,
        Alias = 4,
        WellKnownGroup = 5,
        DeletedAccount = 6,
        Invalid = 7,
        Unknown = 8,
        Computer = 9,
        Label = 10,
        LogonSession = 11
    }

    public static class NativeMethods
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupAccountSid(
            string systemName,
            byte[] sid,
            StringBuilder name,
            ref uint nameLength,
            StringBuilder domainName,
            ref uint domainNameLength,
            out SidNameUse sidNameUse);
    }
}
'@

    Add-Type -TypeDefinition $nativeTypeDefinition -ErrorAction Stop
}

# Функция определения типа субъекта через Windows API LookupAccountSid.
# Возвращает Group, User или Unknown и не изменяет ACL.
function Get-WindowsPrincipalType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid
    )

    # Преобразуем объект SecurityIdentifier в двоичный SID для Win32 API.
    $sidBytes = New-Object byte[] $Sid.BinaryLength
    $Sid.GetBinaryForm($sidBytes, 0)

    # Первый вызов получает требуемые размеры буферов имени и домена.
    [uint32]$nameLength = 0
    [uint32]$domainNameLength = 0
    $sidNameUse = [FolderAclNative.SidNameUse]::Unknown

    $null = [FolderAclNative.NativeMethods]::LookupAccountSid(
        $null,
        $sidBytes,
        $null,
        [ref]$nameLength,
        $null,
        [ref]$domainNameLength,
        [ref]$sidNameUse
    )

    # Код 122 означает ожидаемую ситуацию: переданный буфер недостаточен.
    $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($lastError -ne 122 -and ($nameLength -eq 0 -or $domainNameLength -eq 0)) {
        throw (New-Object System.ComponentModel.Win32Exception($lastError))
    }

    # Второй вызов выполняется с буферами рассчитанного размера и возвращает тип.
    $nameBuilder = New-Object System.Text.StringBuilder([int]$nameLength)
    $domainNameBuilder = New-Object System.Text.StringBuilder([int]$domainNameLength)
    if (-not [FolderAclNative.NativeMethods]::LookupAccountSid(
            $null,
            $sidBytes,
            $nameBuilder,
            [ref]$nameLength,
            $domainNameBuilder,
            [ref]$domainNameLength,
            [ref]$sidNameUse
        )) {
        throw (New-Object System.ComponentModel.Win32Exception(
                [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            ))
    }

    # Приводим Win32-типы Group, Alias и WellKnownGroup к единому типу Group.
    switch ($sidNameUse) {
        { $_ -in @(
                [FolderAclNative.SidNameUse]::Group,
                [FolderAclNative.SidNameUse]::Alias,
                [FolderAclNative.SidNameUse]::WellKnownGroup
            ) } {
            return 'Group'
        }
        ([FolderAclNative.SidNameUse]::User) {
            return 'User'
        }
        default {
            return 'Unknown'
        }
    }
}

# Функция определения типа доменной или локальной учетной записи через ADSI
# WinNT с явно переданными учетными данными.
function Get-AdsiPrincipalType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[^\\]+\\.+$')]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Разделяем DOMAIN\Name и формируем путь WinNT://DOMAIN/Name.
    $accountParts = $AccountName -split '\\', 2
    $networkCredential = $Credential.GetNetworkCredential()
    $adsiPath = 'WinNT://{0}/{1}' -f $accountParts[0], $accountParts[1]
    $entry = $null
    $isBound = $false

    try {
        # Создаем DirectoryEntry с безопасной аутентификацией и принудительно
        # выполняем связывание через обращение к NativeObject.
        $entry = [System.DirectoryServices.DirectoryEntry]::new(
            $adsiPath,
            $Credential.UserName,
            $networkCredential.Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )
        $null = $entry.NativeObject
        $isBound = $true
        $schemaClassName = [string]$entry.SchemaClassName

        # SchemaClassName однозначно разделяет группы и пользователей.
        if ($schemaClassName.Equals('Group', [System.StringComparison]::OrdinalIgnoreCase)) {
            return 'Group'
        }
        if ($schemaClassName.Equals('User', [System.StringComparison]::OrdinalIgnoreCase)) {
            return 'User'
        }

        return 'Unknown'
    }
    finally {
        # Не вызываем Close после неудачного связывания: провайдер WinNT повторит
        # сетевой запрос и может скрыть исходную ошибку исключением очистки.
        if ($isBound -and $null -ne $entry) {
            try {
                $entry.Close()
            }
            catch {
                Write-Verbose -Message ('Не удалось закрыть ADSI-объект {0}: {1}' -f $adsiPath, $_.Exception.Message)
            }
        }
    }
}

# Функция полной классификации SID. Использует кэш, перевод SID в NTAccount,
# системную классификацию, ADSI и резервный LookupAccountSid.
function Get-AclPrincipalClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache,

        [Parameter()]
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Повторяющиеся SID не запрашиваются у домена для каждой папки.
    $cacheKey = $Sid.Value
    if ($Cache.ContainsKey($cacheKey)) {
        return $Cache[$cacheKey]
    }

    # Сначала пытаемся получить читаемое имя DOMAIN\Name.
    $accountName = $null
    try {
        $accountName = $Sid.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch [System.Security.Principal.IdentityNotMappedException] {
        $result = [pscustomobject]@{
            PSTypeName    = 'FolderAcl.PrincipalClassification'
            Sid           = $Sid.Value
            Identity      = $Sid.Value
            PrincipalType = 'OrphanedSid'
            LookupMethod  = 'SidTranslation'
            Detail        = 'SID не сопоставлен с существующей учетной записью.'
        }
        $Cache[$cacheKey] = $result
        return $result
    }
    catch {
        $result = [pscustomobject]@{
            PSTypeName    = 'FolderAcl.PrincipalClassification'
            Sid           = $Sid.Value
            Identity      = $Sid.Value
            PrincipalType = 'Unknown'
            LookupMethod  = 'SidTranslation'
            Detail        = 'Не удалось сопоставить SID: {0}' -f $_.Exception.Message
        }
        $Cache[$cacheKey] = $result
        return $result
    }

    # Разрешенные системные SID без доменной части сохраняются без дополнительных запросов.
    if ($null -eq $Sid.AccountDomainSid) {
        $result = [pscustomobject]@{
            PSTypeName    = 'FolderAcl.PrincipalClassification'
            Sid           = $Sid.Value
            Identity      = $accountName
            PrincipalType = 'SystemPrincipal'
            LookupMethod  = 'SystemSid'
            Detail        = $null
        }
        $Cache[$cacheKey] = $result
        return $result
    }

    # При наличии Credential ADSI является первым способом определения типа.
    $adsiErrorMessage = $null
    if ($null -ne $Credential) {
        try {
            $principalType = Get-AdsiPrincipalType -AccountName $accountName -Credential $Credential
            if ($principalType -ne 'Unknown') {
                $result = [pscustomobject]@{
                    PSTypeName    = 'FolderAcl.PrincipalClassification'
                    Sid           = $Sid.Value
                    Identity      = $accountName
                    PrincipalType = $principalType
                    LookupMethod  = 'AdsiWinNT'
                    Detail        = $null
                }
                $Cache[$cacheKey] = $result
                return $result
            }

            # Неизвестный класс ADSI не является окончательным результатом:
            # передаем SID в LookupAccountSid для безопасной классификации.
            $adsiErrorMessage = 'ADSI WinNT вернула неподдерживаемый тип учетной записи.'
        }
        catch {
            $adsiErrorMessage = $_.Exception.Message
        }
    }

    # Если Credential не задан или ADSI завершилась ошибкой, используем
    # LookupAccountSid через защищенный канал доменного сервера.
    try {
        $principalType = Get-WindowsPrincipalType -Sid $Sid
        $result = [pscustomobject]@{
            PSTypeName    = 'FolderAcl.PrincipalClassification'
            Sid           = $Sid.Value
            Identity      = $accountName
            PrincipalType = $principalType
            LookupMethod  = if ($null -eq $adsiErrorMessage) {
                'LookupAccountSid'
            }
            else {
                'LookupAccountSidFallback'
            }
            Detail        = if ($null -ne $adsiErrorMessage) {
                'ADSI WinNT не определила тип, использован LookupAccountSid: {0}' -f $adsiErrorMessage
            }
            elseif ($principalType -eq 'Unknown') {
                'Windows вернула неподдерживаемый тип учетной записи.'
            }
            else {
                $null
            }
        }
        $Cache[$cacheKey] = $result
        return $result
    }
    catch {
        $result = [pscustomobject]@{
            PSTypeName    = 'FolderAcl.PrincipalClassification'
            Sid           = $Sid.Value
            Identity      = $accountName
            PrincipalType = 'Unknown'
            LookupMethod  = 'Failed'
            Detail        = if ($null -ne $adsiErrorMessage) {
                'Ошибка ADSI WinNT: {0}; ошибка LookupAccountSid: {1}' -f $adsiErrorMessage, $_.Exception.Message
            }
            else {
                'Не удалось определить тип учетной записи через LookupAccountSid: {0}' -f $_.Exception.Message
            }
        }
        $Cache[$cacheKey] = $result
        return $result
    }
}

# Функция преобразования FileSystemAccessRule и результата классификации в
# сериализуемый объект FolderAcl.RuleInfo для консоли и JSON-журнала.
function ConvertTo-FolderAclRuleInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]$Rule,

        [Parameter(Mandatory = $true)]
        [psobject]$Classification
    )

    return [pscustomobject]@{
        PSTypeName        = 'FolderAcl.RuleInfo'
        Identity          = $Classification.Identity
        Sid               = $Classification.Sid
        PrincipalType     = $Classification.PrincipalType
        LookupMethod      = $Classification.LookupMethod
        FileSystemRights  = $Rule.FileSystemRights.ToString()
        AccessControlType = $Rule.AccessControlType.ToString()
        InheritanceFlags  = $Rule.InheritanceFlags.ToString()
        PropagationFlags  = $Rule.PropagationFlags.ToString()
        IsInherited       = $Rule.IsInherited
        Detail            = $Classification.Detail
    }
}

# Функция формирования итогового объекта FolderAcl.CleanupResult по одной папке.
# Объект содержит статус, счетчики и полные массивы правил каждой категории.
function ConvertTo-FolderAclCleanupResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Changed', 'Unchanged', 'WhatIf', 'Excluded', 'SkippedReparsePoint', 'Failed')]
        [string]$Status,

        [Parameter()]
        [AllowNull()]
        [Nullable[bool]]$InheritanceEnabled,

        [Parameter()]
        [bool]$Changed = $false,

        [Parameter()]
        [object[]]$RemovedRules = @(),

        [Parameter()]
        [object[]]$PlannedRules = @(),

        [Parameter()]
        [object[]]$PlannedInheritanceRefreshRules = @(),

        [Parameter()]
        [object[]]$RefreshedInheritedRules = @(),

        [Parameter()]
        [object[]]$PreservedGroupRules = @(),

        [Parameter()]
        [object[]]$PreservedSystemRules = @(),

        [Parameter()]
        [object[]]$SkippedInheritedRules = @(),

        [Parameter()]
        [object[]]$PreservedUnknownRules = @(),

        [Parameter()]
        [AllowNull()]
        [string]$ErrorMessage
    )

    return [pscustomobject]@{
        PSTypeName                          = 'FolderAcl.CleanupResult'
        Path                                = $Path
        Status                              = $Status
        InheritanceEnabled                  = $InheritanceEnabled
        Changed                             = $Changed
        RemovedRuleCount                    = $RemovedRules.Count
        PlannedRemovalCount                 = $PlannedRules.Count
        PlannedInheritanceRefreshRuleCount  = $PlannedInheritanceRefreshRules.Count
        RefreshedInheritedRuleCount         = $RefreshedInheritedRules.Count
        PreservedGroupRuleCount             = $PreservedGroupRules.Count
        PreservedSystemRuleCount            = $PreservedSystemRules.Count
        SkippedInheritedRuleCount           = $SkippedInheritedRules.Count
        PreservedUnknownRuleCount           = $PreservedUnknownRules.Count
        RemovedRules                        = @($RemovedRules)
        PlannedRules                        = @($PlannedRules)
        PlannedInheritanceRefreshRules      = @($PlannedInheritanceRefreshRules)
        RefreshedInheritedRules             = @($RefreshedInheritedRules)
        PreservedGroupRules                 = @($PreservedGroupRules)
        PreservedSystemRules                = @($PreservedSystemRules)
        SkippedInheritedRules               = @($SkippedInheritedRules)
        PreservedUnknownRules               = @($PreservedUnknownRules)
        Error                               = $ErrorMessage
    }
}

# Функция атомарно формирует незащищенную DACL без старых унаследованных ACE.
# При записи Windows повторно получает наследуемые правила от текущего родителя.
function Invoke-FolderAclInheritanceRefresh {
    <#
    .SYNOPSIS
    Принудительно обновляет унаследованные правила ACL папки.

    .DESCRIPTION
    В памяти временно защищает DACL без копирования наследуемых ACE, затем снова
    включает наследование и выполняет единственную запись Set-Acl. Явные ACE,
    владелец и конечное состояние наследования сохраняются. При ошибке проверки
    выполняется попытка восстановить исходный дескриптор безопасности.

    .PARAMETER Path
    Полный путь к папке с включенным наследованием.

    .EXAMPLE
    Invoke-FolderAclInheritanceRefresh -Path 'D:\Data\Child'

    Повторно получает унаследованные ACE папки от ее текущего родителя.

    .NOTES
    Функция является внутренней. Вызывающий код обязан получить разрешение
    ShouldProcess до ее запуска.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.DirectorySecurity])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $originalSddl = $null
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($acl.AreAccessRulesProtected) {
            throw "Наследование ACL папки '$Path' отключено."
        }

        $allSections = [System.Security.AccessControl.AccessControlSections]::All
        $originalSddl = $acl.GetSecurityDescriptorSddlForm($allSections)

        # Два переключения выполняются только над объектом в памяти. На диск
        # записывается сразу итоговая незащищенная DACL без устаревших ACE.
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetAccessRuleProtection($false, $false)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop

        $refreshedAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($refreshedAcl.AreAccessRulesProtected) {
            throw "После обновления наследование ACL папки '$Path' осталось отключенным."
        }

        return $refreshedAcl
    }
    catch {
        $refreshError = $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($originalSddl)) {
            try {
                $rollbackAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $rollbackAcl.SetSecurityDescriptorSddlForm(
                    $originalSddl,
                    [System.Security.AccessControl.AccessControlSections]::All
                )
                Set-Acl -LiteralPath $Path -AclObject $rollbackAcl -ErrorAction Stop
            }
            catch {
                throw "Не удалось обновить наследование ACL папки '$Path': $refreshError Ошибка отката: $($_.Exception.Message)"
            }
        }

        throw "Не удалось обновить наследование ACL папки '$Path': $refreshError"
    }
}

# Функция потоковой записи результатов в валидный JSON-журнал UTF-8 with BOM.
# Каждый входной объект одновременно возвращается дальше в консольный вывод.
function Write-FolderAclResultLog {
    <#
    .SYNOPSIS
    Записывает объекты результата очистки ACL в журнал формата JSON.

    .DESCRIPTION
    Принимает объекты FolderAcl.CleanupResult из конвейера, формирует валидный
    JSON-документ с метаданными запуска и массивом Results, после чего возвращает
    исходные объекты обратно в конвейер без изменения. Файл сохраняется в
    UTF-8 with BOM.

    .PARAMETER InputObject
    Объект результата очистки ACL.

    .PARAMETER LiteralPath
    Полный путь к создаваемому лог-файлу. Существующий файл перезаписывается.

    .PARAMETER ExecutionMode
    Режим выполнения, записываемый в заголовок журнала.

    .EXAMPLE
    Clear-FolderGroupAcl -Path 'D:\Data' -WhatIf |
        Write-FolderAclResultLog -LiteralPath 'D:\Logs\Clear-FolderGroupAcl-WhatIf.log' `
            -ExecutionMode WhatIf

    Записывает результаты предварительной проверки в JSON и сохраняет объектный
    вывод.

    .NOTES
    Создание журнала выполняется и в режиме WhatIf, но ACL при этом не изменяется.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [psobject]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet('WhatIf', 'Apply')]
        [string]$ExecutionMode
    )

    begin {
        # В begin создается каталог, открывается новый файл и записывается
        # заголовок JSON. Файл соответствующего режима перезаписывается.
        $writer = $null
        try {
            $logDirectory = Split-Path -Path $LiteralPath -Parent
            if ([string]::IsNullOrWhiteSpace($logDirectory)) {
                throw "Для лог-файла '$LiteralPath' не указан родительский каталог."
            }
            if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
                $null = New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop
            }

            $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
            $writer = New-Object System.IO.StreamWriter($LiteralPath, $false, $utf8WithBom)
            $startedAt = (Get-Date).ToString('o')
            $modeJson = ConvertTo-Json -InputObject $ExecutionMode -Compress
            $startedAtJson = ConvertTo-Json -InputObject $startedAt -Compress
            $writer.WriteLine('{')
            $writer.WriteLine('  "SchemaVersion": "1.1",')
            $writer.WriteLine(('  "ExecutionMode": {0},' -f $modeJson))
            $writer.WriteLine(('  "StartedAt": {0},' -f $startedAtJson))
            $writer.WriteLine('  "Results": [')
            $isFirstResult = $true
        }
        catch {
            throw "Не удалось создать лог-файл '$LiteralPath': $($_.Exception.Message)"
        }
    }

    process {
        # В process каждый FolderAcl.CleanupResult сериализуется отдельно.
        # Запятая добавляется только между элементами массива Results.
        try {
            if (-not $isFirstResult) {
                $writer.WriteLine(',')
            }

            $resultJson = ConvertTo-Json -InputObject $InputObject -Depth 10
            $writer.Write($resultJson)
            $writer.Flush()
            $isFirstResult = $false
        }
        catch {
            throw "Не удалось записать результат для '$($InputObject.Path)' в лог '$LiteralPath': $($_.Exception.Message)"
        }

        Write-Output -InputObject $InputObject
    }

    end {
        # В end закрывается массив Results, добавляется время завершения и
        # освобождается файловый поток.
        if ($null -ne $writer) {
            $completedAt = (Get-Date).ToString('o')
            $completedAtJson = ConvertTo-Json -InputObject $completedAt -Compress
            $writer.WriteLine()
            $writer.WriteLine('  ],')
            $writer.WriteLine(('  "CompletedAt": {0}' -f $completedAtJson))
            $writer.WriteLine('}')
            $writer.Dispose()
        }
    }
}

# Основная функция обхода дерева и очистки ACL. Поддерживает ShouldProcess,
# поэтому режимы -WhatIf и -Confirm обрабатываются стандартным механизмом PowerShell.
function Clear-FolderGroupAcl {
    <#
    .SYNOPSIS
    Удаляет из ACL папок прямые назначения пользователям и осиротевшие SID.

    .DESCRIPTION
    Обрабатывает указанную корневую папку и все вложенные папки сверху вниз.
    Владелец, конечное состояние наследования, групповые и системные правила не
    изменяются. Явные правила пользователей и неразрешаемых SID удаляются.
    Для устаревших унаследованных правил функция может принудительно повторно
    получить ACL от очищенного родителя. Папки из списка исключений и все их
    поддеревья пропускаются. Повторная обработка не изменяет уже очищенный ACL,
    поэтому функция идемпотентна.

    .PARAMETER Path
    Путь к верхней папке обрабатываемого дерева. Обрабатывается сама папка и все
    вложенные каталоги. Поддерживаются локальные и UNC-пути, а также конвейер.

    .PARAMETER ExcludeFolderName
    Точные имена папок, которые требуется исключить вместе со всем их поддеревом.
    Сравнение имен выполняется без учета регистра.

    .PARAMETER Credential
    Учетные данные для проверки типа учетных записей через ADSI WinNT. Если
    ADSI недоступна, автоматически используется LookupAccountSid.

    .PARAMETER RefreshStaleInheritance
    При значении true принудительно обновляет наследование папок, в которых
    обнаружены унаследованные правила пользователей или осиротевших SID.

    .EXAMPLE
    Clear-FolderGroupAcl -Path 'D:\example1\example2\example3' -WhatIf

    Показывает план очистки без изменения ACL.

    .EXAMPLE
    Clear-FolderGroupAcl -Path 'D:\example1\example2\example3' `
        -ExcludeFolderName 'Archive', 'DoNotTouch' -Confirm:$false

    Очищает дерево, кроме папок Archive, DoNotTouch и всех их вложенных папок.

    .EXAMPLE
    [pscustomobject]@{ FullName = '\\FS01\Share\example3' } |
        Clear-FolderGroupAcl -ExcludeFolderName 'Service' -Confirm:$false

    Передает UNC-путь через свойство FullName объекта конвейера.

    .NOTES
    Требуются PowerShell 5.1 и права чтения и изменения DACL. Тип доменных и
    локальных учетных записей определяется штатной функцией Windows
    LookupAccountSid. Модуль ActiveDirectory не требуется. Запускайте сначала
    с параметром -WhatIf. Функция не изменяет владельца.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'LiteralPath', 'PSPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [Parameter()]
        [Alias('Exclude')]
        [ValidateNotNull()]
        [ValidatePattern('^[^\\/:*?"<>|]+$')]
        [string[]]$ExcludeFolderName = @(),

        [Parameter()]
        [AllowNull()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [bool]$RefreshStaleInheritance = $true
    )

    begin {
        # Создаем общий кэш классификации SID для всего запуска, набор уже
        # обработанных корней и регистронезависимый набор исключений.
        $principalCache = @{}
        $processedRoots = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $excludedNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($excludedName in $ExcludeFolderName) {
            $null = $excludedNames.Add($excludedName)
        }
    }

    process {
        foreach ($inputPath in $Path) {
            # Проверяем существование корневого пути, тип Directory и исключаем
            # повторную обработку одного корня из конвейера.
            try {
                $rootItem = Get-Item -LiteralPath $inputPath -Force -ErrorAction Stop
                if (-not $rootItem.PSIsContainer) {
                    throw "Путь '$inputPath' не является папкой."
                }

                $rootPath = $rootItem.FullName
                if (-not $processedRoots.Add($rootPath)) {
                    Write-Verbose -Message ("Повторный корневой путь пропущен: '{0}'." -f $rootPath)
                    continue
                }
            }
            catch {
                Write-Error -Message ("Не удалось открыть корневую папку '{0}': {1}" -f $inputPath, $_.Exception.Message) -ErrorAction Continue
                ConvertTo-FolderAclCleanupResult -Path $inputPath -Status 'Failed' -ErrorMessage $_.Exception.Message
                continue
            }

            # Очередь обеспечивает обход сверху вниз: родитель всегда
            # обрабатывается раньше дочерней папки.
            $queue = New-Object 'System.Collections.Generic.Queue[string]'
            $queue.Enqueue($rootPath)

            while ($queue.Count -gt 0) {
                $currentPath = $queue.Dequeue()
                $currentName = Split-Path -Path $currentPath -Leaf

                # Совпадение по имени исключает текущую папку и всю ее ветку:
                # дочерние каталоги не добавляются в очередь.
                if ($excludedNames.Contains($currentName)) {
                    Write-Verbose -Message ("Исключена папка и ее поддерево: '{0}'." -f $currentPath)
                    ConvertTo-FolderAclCleanupResult -Path $currentPath -Status 'Excluded'
                    continue
                }

                # Для каждой папки создаются отдельные коллекции правил, чтобы
                # вернуть полный отчет независимо от результата изменения ACL.
                $removedRules = New-Object 'System.Collections.Generic.List[object]'
                $plannedRules = New-Object 'System.Collections.Generic.List[object]'
                $plannedInheritanceRefreshRules = New-Object 'System.Collections.Generic.List[object]'
                $refreshedInheritedRules = New-Object 'System.Collections.Generic.List[object]'
                $preservedGroupRules = New-Object 'System.Collections.Generic.List[object]'
                $preservedSystemRules = New-Object 'System.Collections.Generic.List[object]'
                $skippedInheritedRules = New-Object 'System.Collections.Generic.List[object]'
                $preservedUnknownRules = New-Object 'System.Collections.Generic.List[object]'
                $inheritanceEnabled = $null
                $changed = $false
                $status = 'Unchanged'
                $errorMessages = New-Object 'System.Collections.Generic.List[string]'

                try {
                    # Читаем ACL один раз, сохраняем исходный признак наследования
                    # и получаем явные и унаследованные ACE в виде SID.
                    $acl = Get-Acl -LiteralPath $currentPath -ErrorAction Stop
                    $inheritanceEnabled = -not $acl.AreAccessRulesProtected
                    $accessRules = $acl.GetAccessRules(
                        $true,
                        $true,
                        [System.Security.Principal.SecurityIdentifier]
                    )
                    $rulesToRemove = New-Object 'System.Collections.Generic.List[System.Security.AccessControl.FileSystemAccessRule]'

                    # Каждое правило классифицируется и помещается в одну из
                    # категорий: группа, система, удаление, наследование или Unknown.
                    foreach ($rule in $accessRules) {
                        $sid = [System.Security.Principal.SecurityIdentifier]$rule.IdentityReference
                        $classification = Get-AclPrincipalClassification `
                            -Sid $sid `
                            -Cache $principalCache `
                            -Credential $Credential
                        $ruleInfo = ConvertTo-FolderAclRuleInfo -Rule $rule -Classification $classification

                        switch ($classification.PrincipalType) {
                            'Group' {
                                [void]$preservedGroupRules.Add($ruleInfo)
                            }
                            'SystemPrincipal' {
                                [void]$preservedSystemRules.Add($ruleInfo)
                            }
                            { $_ -in @('User', 'OrphanedSid') } {
                                if ($rule.IsInherited) {
                                    if ($RefreshStaleInheritance -and $inheritanceEnabled) {
                                        [void]$plannedInheritanceRefreshRules.Add($ruleInfo)
                                    }
                                    else {
                                        [void]$skippedInheritedRules.Add($ruleInfo)
                                    }
                                }
                                else {
                                    [void]$rulesToRemove.Add($rule)
                                    [void]$plannedRules.Add($ruleInfo)
                                }
                            }
                            default {
                                [void]$preservedUnknownRules.Add($ruleInfo)
                            }
                        }
                    }

                    # Изменение выполняется только при наличии явных User или
                    # OrphanedSid и только после разрешения ShouldProcess.
                    if ($rulesToRemove.Count -gt 0) {
                        $operation = 'Удалить {0} пользовательских или осиротевших правил ACL' -f $rulesToRemove.Count
                        if ($PSCmdlet.ShouldProcess($currentPath, $operation)) {
                            # Удаляем точные ACE без пересоздания сохраненных
                            # групповых и системных правил.
                            foreach ($ruleToRemove in $rulesToRemove) {
                                $acl.RemoveAccessRuleSpecific($ruleToRemove)
                            }

                            # Записываем DACL. Владелец и признак защиты
                            # наследования остаются такими же, как при Get-Acl.
                            Set-Acl -LiteralPath $currentPath -AclObject $acl -ErrorAction Stop
                            foreach ($plannedRule in $plannedRules) {
                                [void]$removedRules.Add($plannedRule)
                            }
                            $changed = $true
                            $status = 'Changed'
                        }
                        else {
                            $status = 'WhatIf'
                        }
                    }

                    # Если после обработки родителя остались нежелательные
                    # унаследованные ACE, повторно формируем наследуемую часть DACL.
                    if ($plannedInheritanceRefreshRules.Count -gt 0) {
                        $operation = 'Обновить наследование для проверки {0} пользовательских или осиротевших правил ACL' -f $plannedInheritanceRefreshRules.Count
                        if ($PSCmdlet.ShouldProcess($currentPath, $operation)) {
                            $acl = Invoke-FolderAclInheritanceRefresh -Path $currentPath
                            $refreshedAccessRules = $acl.GetAccessRules(
                                $true,
                                $true,
                                [System.Security.Principal.SecurityIdentifier]
                            )
                            $remainingInheritedSid = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                            foreach ($refreshedRule in $refreshedAccessRules) {
                                if ($refreshedRule.IsInherited) {
                                    [void]$remainingInheritedSid.Add($refreshedRule.IdentityReference.Value)
                                }
                            }

                            foreach ($plannedRefreshRule in $plannedInheritanceRefreshRules) {
                                if ($remainingInheritedSid.Contains($plannedRefreshRule.Sid)) {
                                    $plannedRefreshRule.Detail = 'Правило повторно получено от текущего родителя; удалите его в фактической папке-источнике.'
                                    [void]$skippedInheritedRules.Add($plannedRefreshRule)
                                }
                                else {
                                    [void]$refreshedInheritedRules.Add($plannedRefreshRule)
                                }
                            }

                            $changed = $true
                            $status = 'Changed'
                        }
                        else {
                            $status = 'WhatIf'
                        }
                    }
                }
                catch {
                    [void]$errorMessages.Add(('Ошибка ACL: {0}' -f $_.Exception.Message))
                    Write-Error -Message ("Ошибка обработки ACL папки '{0}': {1}" -f $currentPath, $_.Exception.Message) -ErrorAction Continue
                    $status = 'Failed'
                }

                # После обработки ACL перечисляем только дочерние каталоги.
                # Точки повторной обработки не добавляются в очередь.
                $skippedReparsePoints = New-Object 'System.Collections.Generic.List[string]'
                try {
                    $childDirectories = Get-ChildItem -LiteralPath $currentPath -Directory -Force -ErrorAction Stop
                    foreach ($childDirectory in $childDirectories) {
                        if ($childDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                            [void]$skippedReparsePoints.Add($childDirectory.FullName)
                            continue
                        }
                        $queue.Enqueue($childDirectory.FullName)
                    }
                }
                catch {
                    [void]$errorMessages.Add(('Ошибка обхода: {0}' -f $_.Exception.Message))
                    Write-Error -Message ("Не удалось перечислить вложенные папки '{0}': {1}" -f $currentPath, $_.Exception.Message) -ErrorAction Continue
                    $status = 'Failed'
                }

                # Возвращаем один итоговый объект по текущей папке.
                ConvertTo-FolderAclCleanupResult `
                    -Path $currentPath `
                    -Status $status `
                    -InheritanceEnabled $inheritanceEnabled `
                    -Changed $changed `
                    -RemovedRules $removedRules.ToArray() `
                    -PlannedRules $plannedRules.ToArray() `
                    -PlannedInheritanceRefreshRules $plannedInheritanceRefreshRules.ToArray() `
                    -RefreshedInheritedRules $refreshedInheritedRules.ToArray() `
                    -PreservedGroupRules $preservedGroupRules.ToArray() `
                    -PreservedSystemRules $preservedSystemRules.ToArray() `
                    -SkippedInheritedRules $skippedInheritedRules.ToArray() `
                    -PreservedUnknownRules $preservedUnknownRules.ToArray() `
                    -ErrorMessage ($errorMessages -join ' ')

                # Для каждой пропущенной точки повторной обработки возвращается
                # отдельный объект, чтобы пропуск был виден в отчете и журнале.
                foreach ($reparsePointPath in $skippedReparsePoints) {
                    ConvertTo-FolderAclCleanupResult -Path $reparsePointPath -Status 'SkippedReparsePoint'
                }
            }
        }
    }
}

# Основной блок запуска. При точечном подключении экспортируются функции, а
# запрос Credential, очистка ACL и создание журнала не выполняются.
if ($MyInvocation.InvocationName -ne '.') {
    # Формируем набор параметров для основной функции.
    $invokeParameters = @{
        Path                    = $Path
        ExcludeFolderName       = $ExcludeFolderName
        RefreshStaleInheritance = $RefreshStaleInheritance
    }

    # При включенной ADSI-проверке запрашиваем пароль интерактивно. Пароль не
    # хранится в исходном коде и не попадает в JSON-журнал.
    if ($UseAdsiCredential) {
        $credentialParameters = @{
            Message = 'Введите доменную учетную запись для проверки ACL через ADSI WinNT.'
        }
        if (-not [string]::IsNullOrWhiteSpace($AdsiAccountName)) {
            $credentialParameters['UserName'] = $AdsiAccountName
        }

        $adsiCredential = Get-Credential @credentialParameters
        if ($null -eq $adsiCredential) {
            throw 'Запрос учетных данных ADSI отменен пользователем.'
        }
        $invokeParameters['Credential'] = $adsiCredential
    }

    # Преобразуем удобный параметр ExecutionMode в стандартные общие параметры
    # PowerShell -WhatIf или -Confirm.
    if ($ExecutionMode -eq 'WhatIf') {
        $invokeParameters['WhatIf'] = $true
    }
    else {
        $invokeParameters['Confirm'] = $ConfirmChanges
    }

    $nowDate = (Get-Date).ToString("yyyyMMddHHmmss")
    $logFileName = 'Clear-FolderGroupAcl-{0}-{1}.log' -f $ExecutionMode, $nowDate
    $logFilePath = Join-Path -Path $logDirectory -ChildPath $logFileName

    # Результаты одновременно выводятся в консоль и записываются в JSON.
    Clear-FolderGroupAcl @invokeParameters |
        Write-FolderAclResultLog -LiteralPath $logFilePath -ExecutionMode $ExecutionMode
}
