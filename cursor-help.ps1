# Установка кодировки для поддержки Unicode
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$Host.UI.RawUI.WindowTitle = "Cursor Helper"

# Настройка ANSI-цветов
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSStyle.OutputRendering = 'ANSI'
    $RED = "`e[31m"
    $GREEN = "`e[32m"
    $YELLOW = "`e[33m"
    $BLUE = "`e[34m"
    $NC = "`e[0m"
} else {
    $RED = "$([char]0x1b)[31m"
    $GREEN = "$([char]0x1b)[32m"
    $YELLOW = "$([char]0x1b)[33m"
    $BLUE = "$([char]0x1b)[34m"
    $NC = "$([char]0x1b)[0m"
}

# Текущий язык (автоматически английский)
$LANG_CHOICE = "en"

# Функция перевода
function Translate {
    param (
        [string]$key
    )
    
    # Только английский язык
    switch ($key) {
        "info" { "[INFO]" }
        "warn" { "[WARNING]" }
        "error" { "[ERROR]" }
        "debug" { "[DEBUG]" }
        "get_user_error" { "Failed to get username" }
        "run_with_admin" { "Please run script as administrator" }
        "example" { "Example:" }
        "checking_cursor" { "Checking Cursor process..." }
        "process_info" { "Getting process info" }
        "cursor_not_found" { "No Cursor process found" }
        "cursor_found" { "Found running Cursor process" }
        "killing_attempt" { "Attempting to kill process..." }
        "force_kill" { "Forcing termination..." }
        "cursor_killed" { "Cursor process successfully terminated" }
        "waiting_termination" { "Waiting for termination, attempt" }
        "kill_failed" { "Failed to terminate process after" }
        "kill_manual" { "Please terminate process manually and try again" }
        "backup_skipped" { "Configuration file doesn't exist, skipping backup" }
        "backup_created" { "Backup created at:" }
        "backup_failed" { "Backup creation failed" }
        "config_not_found" { "Configuration file not found:" }
        "install_first" { "Please install and run Cursor at least once" }
        "config_updated" { "Configuration updated:" }
        "rights_failed" { "Failed to set read-only permissions" }
        "rights_success" { "Access rights set successfully" }
        "file_structure" { "File structure:" }
        "modified" { "modified" }
        "empty" { "empty" }
        "follow_telegram" { "Follow our Telegram channel @exmodium" }
        "tool_name" { "Cursor Bypass Tool" }
        "important" { "IMPORTANT" }
        "version_support" { "Current Cursor version is supported" }
        "version_not_support" { "" }
        "done" { "Done!" }
        "restart_required" { "Restart Cursor to apply changes" }
        "disable_auto_update" { "Disable Cursor auto-update?" }
        "no" { "No - keep default settings (Press Enter)" }
        "yes" { "Yes - disable auto-update" }
        "disabling_update" { "Disabling auto-update..." }
        "manual_steps" { "Automatic setup failed. Manual steps:" }
        "open_terminal" { "Open PowerShell as administrator" }
        "run_commands" { "Run these commands:" }
        "if_no_rights" { "If permission denied:" }
        "verification" { "Verification:" }
        "check_rights" { "Verify file is read-only" }
        "restart_after" { "Restart Cursor after completion" }
        "folder_deleted" { "cursor-updater folder deleted" }
        "folder_delete_failed" { "Failed to delete cursor-updater folder" }
        "file_create_failed" { "Failed to create file" }
        "rights_check_failed" { "Rights check failed" }
        "update_disabled" { "Auto-update disabled" }
        "update_enabled" { "Auto-update remains enabled" }
        "current_machineguid" { "Current MachineGuid:" }
        "machineguid_updated" { "MachineGuid successfully updated to:" }
        default { "[$key]" }
    }
}

# Функции логирования
function Write-LogInfo {
    param([string]$Message)
    Write-Host "$GREEN$(Translate 'info')$NC $Message"
}

function Write-LogWarn {
    param([string]$Message)
    Write-Host "$YELLOW$(Translate 'warn')$NC $Message"
}

function Write-LogError {
    param([string]$Message)
    Write-Host "$RED$(Translate 'error')$NC $Message"
}

function Write-LogDebug {
    param([string]$Message)
    Write-Host "$BLUE$(Translate 'debug')$NC $Message"
}

# Проверка прав администратора
function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-LogError $(Translate "run_with_admin")
        Write-Host "$(Translate 'example'): Start-Process powershell -Verb RunAs -ArgumentList `"-File `"$PSCommandPath`"`""
        exit 1
    }
}

# Пути к файлам
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# Убрана функция выбора языка - всегда английский

# Проверка и завершение процесса Cursor
function Stop-CursorProcess {
    Write-LogInfo $(Translate "checking_cursor")
    
    $attempt = 1
    $maxAttempts = 5
    
    function Get-ProcessDetails {
        param([string]$ProcessName)
        Write-LogDebug "$(Translate 'process_info') $ProcessName"
        Get-Process | Where-Object { $_.ProcessName -like "*$ProcessName*" } | Format-Table -AutoSize
    }
    
    while ($attempt -le $maxAttempts) {
        $cursorProcess = Get-Process "Cursor" -ErrorAction SilentlyContinue
        
        if (-not $cursorProcess) {
            Write-LogInfo $(Translate "cursor_not_found")
            return
        }
        
        Write-LogWarn $(Translate "cursor_found")
        Get-ProcessDetails "Cursor"
        
        Write-LogWarn $(Translate "killing_attempt")
        
        if ($attempt -eq $maxAttempts) {
            Write-LogWarn $(Translate "force_kill")
            $cursorProcess | Stop-Process -Force -ErrorAction SilentlyContinue
        } else {
            $cursorProcess | Stop-Process -ErrorAction SilentlyContinue
        }
        
        Start-Sleep -Seconds 1
        
        if (-not (Get-Process "Cursor" -ErrorAction SilentlyContinue)) {
            Write-LogInfo $(Translate "cursor_killed")
            return
        }
        
        Write-LogWarn "$(Translate 'waiting_termination') $attempt/$maxAttempts..."
        $attempt++
    }
    
    Write-LogError "$(Translate 'kill_failed') $maxAttempts"
    Get-ProcessDetails "Cursor"
    Write-LogError $(Translate "kill_manual")
    exit 1
}

# Резервное копирование
function Backup-Config {
    if (-not (Test-Path $STORAGE_FILE)) {
        Write-LogWarn $(Translate "backup_skipped")
        return
    }
    
    New-Item -ItemType Directory -Force -Path $BACKUP_DIR | Out-Null
    $backupFile = Join-Path $BACKUP_DIR "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    
    try {
        Copy-Item $STORAGE_FILE $backupFile
        Write-LogInfo "$(Translate 'backup_created') $backupFile"
    } catch {
        Write-LogError $(Translate "backup_failed")
        exit 1
    }
}

# Генерация случайного ID
function New-RandomId {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    return [System.BitConverter]::ToString($bytes) -replace '-',''
}

# Генерация UUID
function New-UUID {
    return [guid]::NewGuid().ToString().ToLower()
}

# Генерация новой конфигурации
function Update-Config {
    if (-not (Test-Path $STORAGE_FILE)) {
        Write-LogError "$(Translate 'config_not_found') $STORAGE_FILE"
        Write-LogWarn $(Translate "install_first")
        exit 1
    }
    
    $machineId = "authuser_" + (New-RandomId)
    $macMachineId = New-RandomId
    $deviceId = New-UUID
    $sqmId = "{" + (New-UUID).ToUpper() + "}"
    
    try {
        # Снимаем все атрибуты файла
        attrib -r -h -s $STORAGE_FILE

        # Читаем и обновляем конфигурацию
        $config = Get-Content $STORAGE_FILE -Raw | ConvertFrom-Json
        $config.'telemetry.machineId' = $machineId
        $config.'telemetry.macMachineId' = $macMachineId
        $config.'telemetry.devDeviceId' = $deviceId
        $config.'telemetry.sqmId' = $sqmId
        
        # Сохраняем обновленную конфигурацию
        $config | ConvertTo-Json -Depth 100 | Set-Content $STORAGE_FILE

        # Устанавливаем атрибут "только для чтения" через командную строку
        attrib +r $STORAGE_FILE

        Write-Host
        Write-LogInfo $(Translate "config_updated")
        Write-LogDebug "machineId: $machineId"
        Write-LogDebug "macMachineId: $macMachineId"
        Write-LogDebug "deviceId: $deviceId"
        Write-LogDebug "sqmId: $sqmId"
        
    } catch {
        Write-LogError $_.Exception.Message
        Write-LogError $(Translate "run_with_admin")
        exit 1
    }
}

# Отображение структуры файлов
function Show-FileTree {
    Write-Host
    Write-LogInfo $(Translate "file_structure")
    $baseDir = Split-Path $STORAGE_FILE -Parent
    Write-Host "$BLUE$baseDir$NC"
    Write-Host "├── globalStorage"
    Write-Host "│   ├── storage.json ($(Translate 'modified'))"
    Write-Host "│   └── backups"
    
    if (Test-Path $BACKUP_DIR) {
        $backupFiles = Get-ChildItem $BACKUP_DIR -File
        if ($backupFiles.Count -gt 0) {
            foreach ($file in $backupFiles) {
                Write-Host "│       └── $($file.Name)"
            }
        } else {
            Write-Host "│       └── ($(Translate 'empty'))"
        }
    }
    Write-Host
}

# Информация о Telegram
function Show-FollowInfo {
    Write-Host
    Write-Host "$GREEN================================$NC"
    Write-Host "$YELLOW  $(Translate 'follow_telegram') $NC"
    Write-Host "$GREEN================================$NC"
    Write-Host
}

# Отключение автообновлений (автоматически выбирает опцию 2)
function Disable-AutoUpdate {
    Write-Host
    Write-LogWarn $(Translate "disable_auto_update")
    Write-Host "1) $(Translate 'no')"
    Write-Host "2) $(Translate 'yes')"
    
    # Автоматически выбираем опцию 2
    $choice = "2"
    Write-Host "Auto-selected: 2 (disable auto-update)"
    
    if ($choice -eq "2") {
        Write-Host
        Write-LogInfo $(Translate "disabling_update")
        $updaterPath = "$env:APPDATA\cursor-updater"
        
        try {
            if (Test-Path $updaterPath) {
                Remove-Item $updaterPath -Force -Recurse
                Write-LogInfo $(Translate "folder_deleted")
            }
            
            New-Item -ItemType File $updaterPath -Force | Out-Null
            Set-ItemProperty $updaterPath -Name IsReadOnly -Value $true
            
            if (-not (Test-Path $updaterPath) -or (Get-Item $updaterPath).IsReadOnly -eq $false) {
                Write-LogError $(Translate "rights_check_failed")
                Write-Host
                Write-LogWarn $(Translate "manual_steps")
                Write-Host "$YELLOW$(Translate 'open_terminal')$NC"
                Write-Host "$(Translate 'run_commands'):"
                Write-Host "$BLUE`"rm -r '$updaterPath'; New-Item -ItemType File '$updaterPath'; Set-ItemProperty '$updaterPath' -Name IsReadOnly -Value `$true`"$NC"
                Write-Host
                Write-Host "$YELLOW$(Translate 'verification')$NC"
                Write-Host "Get-ItemProperty '$updaterPath'"
                Write-Host "$(Translate 'check_rights')"
                Write-Host
                Write-LogWarn $(Translate "restart_after")
                return
            }
            
            Write-LogInfo $(Translate "update_disabled")
        } catch {
            Write-LogError $(Translate "file_create_failed")
            Write-Host
            Write-LogWarn $(Translate "manual_steps")
            Write-Host "$YELLOW$(Translate 'open_terminal')$NC"
            Write-Host "$(Translate 'run_commands'):"
            Write-Host "$BLUE`"rm -r '$updaterPath'; New-Item -ItemType File '$updaterPath'; Set-ItemProperty '$updaterPath' -Name IsReadOnly -Value `$true`"$NC"
            Write-Host
            Write-Host "$YELLOW$(Translate 'verification')$NC"
            Write-Host "Get-ItemProperty '$updaterPath'"
            Write-Host "$(Translate 'check_rights')"
            Write-Host
            Write-LogWarn $(Translate "restart_after")
        }
    } else {
        Write-LogInfo $(Translate "update_enabled")
    }
}

# Добавляем функцию для обновления MachineGuid
function Update-MachineGuid {
    try {
        $newGuid = [guid]::NewGuid().ToString()
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        
        $currentGuid = Get-ItemPropertyValue -Path $registryPath -Name "MachineGuid"
        Write-LogInfo "$(Translate 'current_machineguid') $currentGuid"
        
        Set-ItemProperty -Path $registryPath -Name "MachineGuid" -Value $newGuid -Force
        
        $updatedGuid = Get-ItemPropertyValue -Path $registryPath -Name "MachineGuid"
        if ($updatedGuid -eq $newGuid) {
            Write-LogInfo "$(Translate 'machineguid_updated') $newGuid"
        } else {
            Write-LogError "MachineGuid update failed"
        }
    } catch {
        Write-LogError "Error updating MachineGuid: $_"
    }
}

# Функция для открытия сайта
function Open-Website {
    $sites = @("https://assets-hub.ru", "https://assets-hub.pro")
    $randomSite = $sites | Get-Random
    try {
        Start-Process $randomSite
        
    } catch {
        Write-LogError "Failed to open website: $_"
    }
}

# Главная функция
function Start-Main {
    Clear-Host
    # Язык уже выбран как английский по умолчанию
    Write-Host @"
    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"@
    Write-Host "$BLUE================================$NC"
    Write-Host "$GREEN      $(Translate 'tool_name')         $NC"
    Write-Host "$BLUE================================$NC"
    Write-Host
    Write-Host "$YELLOW[$(Translate 'important')]$NC $(Translate 'version_support')"
    Write-Host
    
    Test-AdminRights
    Stop-CursorProcess
    Backup-Config
    Update-Config
    Update-MachineGuid
    
    Write-Host
    Write-LogInfo $(Translate "done")
    Show-FileTree
    Show-FollowInfo
    Write-LogInfo $(Translate "restart_required")
    
    # Автоматически отключаем автообновление
    Disable-AutoUpdate
}

# Запуск главной функции
Start-Main
