Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Colors
$colorFormBack = [System.Drawing.Color]::FromArgb(245,245,245)
$colorLabelFore = [System.Drawing.Color]::FromArgb(0,70,130)
$colorSignatureFore = [System.Drawing.Color]::FromArgb(100,100,100)

# Main form setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "EA Denuvo Token Dumper"
$form.Size = New-Object System.Drawing.Size(700,580)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.BackColor = $colorFormBack
$form.TopMost = $true

# License file label and textbox
$lblDLF = New-Object System.Windows.Forms.Label
$lblDLF.Text = "License file:"
$lblDLF.Font = New-Object System.Drawing.Font("Segoe UI",11,[System.Drawing.FontStyle]::Bold)
$lblDLF.ForeColor = $colorLabelFore
$lblDLF.Location = "20,15"
$form.Controls.Add($lblDLF)

$txtDLF = New-Object System.Windows.Forms.TextBox
$txtDLF.Size = "530,28"
$txtDLF.Location = "20,40"
$txtDLF.Font = New-Object System.Drawing.Font("Segoe UI",10)
$txtDLF.Text = Join-Path $env:SystemDrive 'ProgramData\Electronic Arts\EA Services\License\16425677_sc.dlf'
$form.Controls.Add($txtDLF)

$btnDLF = New-Object System.Windows.Forms.Button
$btnDLF.Text = "Browse"
$btnDLF.Location = "565,39"
$btnDLF.Size = "90,30"
$btnDLF.Font = New-Object System.Drawing.Font("Segoe UI",9)
$btnDLF.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = "Select License File"
    $ofd.Filter = "DLF files (*.dlf)|*.dlf|All files (*.*)|*.*"
    $ofd.InitialDirectory = Split-Path $txtDLF.Text -Parent
    if ($ofd.ShowDialog() -eq "OK") { $txtDLF.Text = $ofd.FileName }
})
$form.Controls.Add($btnDLF)

# Config file label and textbox
$lblCFG = New-Object System.Windows.Forms.Label
$lblCFG.Text = "Config file:"
$lblCFG.Font = New-Object System.Drawing.Font("Segoe UI",11,[System.Drawing.FontStyle]::Bold)
$lblCFG.ForeColor = $colorLabelFore
$lblCFG.Location = "20,80"
$form.Controls.Add($lblCFG)

$txtCFG = New-Object System.Windows.Forms.TextBox
$txtCFG.Size = "530,28"
$txtCFG.Location = "20,105"
$txtCFG.Font = New-Object System.Drawing.Font("Segoe UI",10)

# ✅ FIXED: safer way to find script/exe directory
$scriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ([System.Reflection.Assembly]::GetEntryAssembly()) {
    Split-Path -Parent ([System.Reflection.Assembly]::GetEntryAssembly().Location)
} else {
    Get-Location
}
$txtCFG.Text = Join-Path $scriptDir "anadius.cfg"
$form.Controls.Add($txtCFG)

$btnCFG = New-Object System.Windows.Forms.Button
$btnCFG.Text = "Browse"
$btnCFG.Location = "565,104"
$btnCFG.Size = "90,30"
$btnCFG.Font = New-Object System.Drawing.Font("Segoe UI",9)
$btnCFG.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = "Select Config File"
    $ofd.Filter = "CFG files (*.cfg)|*.cfg|All files (*.*)|*.*"
    $ofd.InitialDirectory = Split-Path $txtCFG.Text -Parent
    if ($ofd.ShowDialog() -eq "OK") { $txtCFG.Text = $ofd.FileName }
})
$form.Controls.Add($btnCFG)

# Checkbox for config update
$chkOverwrite = New-Object System.Windows.Forms.CheckBox
$chkOverwrite.Text = "Add DenuvoToken to anadius.cfg even if it exists"
$chkOverwrite.Location = "20,145"
$chkOverwrite.Font = New-Object System.Drawing.Font("Segoe UI",10)
$chkOverwrite.Width = 450
$chkOverwrite.Checked = $true
$form.Controls.Add($chkOverwrite)

# Enable/disable config path controls based on checkbox
$chkOverwrite.Add_CheckedChanged({
    $txtCFG.Enabled = $chkOverwrite.Checked
    $btnCFG.Enabled = $chkOverwrite.Checked
})

$txtCFG.Enabled = $chkOverwrite.Checked
$btnCFG.Enabled = $chkOverwrite.Checked

# Start button
$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = "Start"
$btnStart.Font = New-Object System.Drawing.Font("Segoe UI",12,[System.Drawing.FontStyle]::Bold)
$btnStart.Location = "565,185"
$btnStart.Size = "90,40"
$form.Controls.Add($btnStart)

# DenuvoToken label and textbox
$lblTokenTitle = New-Object System.Windows.Forms.Label
$lblTokenTitle.Text = "DenuvoToken:"
$lblTokenTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblTokenTitle.ForeColor = $colorLabelFore
$lblTokenTitle.Location = "20,245"
$lblTokenTitle.Size = "640,25"
$form.Controls.Add($lblTokenTitle)

$txtToken = New-Object System.Windows.Forms.TextBox
$txtToken.Location = "20,275"
$txtToken.Size = "635,180"
$txtToken.Font = New-Object System.Drawing.Font("Consolas",10)
$txtToken.Multiline = $true
$txtToken.ScrollBars = "Vertical"
$txtToken.ReadOnly = $true
$form.Controls.Add($txtToken)

# Progress bar
$pbar = New-Object System.Windows.Forms.ProgressBar
$pbar.Style = "Continuous"
$pbar.Location = "20,470"
$pbar.Size = "635,25"
$form.Controls.Add($pbar)

# Signature label bottom center
$lblSignature = New-Object System.Windows.Forms.LinkLabel
$lblSignature.Text = "Made by RMC`nThanks to Sodium and anadius`nApp GitHub Repo: https://github.com/RMC-4/EA-License-Token-Dumper/"

# Find the start of the URL inside the text
$startIndex = $lblSignature.Text.IndexOf("https://github.com/RMC-4/EA-License-Token-Dumper/")
$null = $lblSignature.Links.Add($startIndex, ($lblSignature.Text.Length - $startIndex), "https://github.com/RMC-4/EA-License-Token-Dumper/")

$lblSignature.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$lblSignature.LinkColor = [System.Drawing.Color]::FromArgb(0, 70, 130)   # blue
$lblSignature.ActiveLinkColor = [System.Drawing.Color]::FromArgb(0, 70, 130) # stay blue when clicked
$lblSignature.VisitedLinkColor = [System.Drawing.Color]::FromArgb(0, 70, 130) # stay blue after visited
$lblSignature.AutoSize = $true
$lblSignature.TextAlign = 'MiddleCenter'

# Open link in browser when clicked
$lblSignature.add_LinkClicked({
    Start-Process $lblSignature.Links[0].LinkData
})

$form.Controls.Add($lblSignature)

# Center below progress bar
$form.Add_Shown({
    $x = [int](($form.ClientSize.Width - $lblSignature.PreferredWidth) / 2)
    $y = $pbar.Location.Y + $pbar.Height + 5
    $lblSignature.Location = New-Object System.Drawing.Point($x, $y)
})

# ✅ Updated Show-Message function
function Show-Message {
    param(
        [string]$text,
        [string]$title,
        [string]$icon = 'None',
        [switch]$AlsoToToken
    )
    [System.Windows.Forms.MessageBox]::Show(
        $text, $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::$icon
    ) | Out-Null

    if ($AlsoToToken) {
        $txtToken.Text = $text
    }
}

function Sleep-And-Update([int]$ms) {
    Start-Sleep -Milliseconds $ms
    [System.Windows.Forms.Application]::DoEvents()
}

function Try-Decrypt {
    param($inputBytes, $keyBytes, $iv)
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keyBytes
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch { return $null }
}

$btnStart.Add_Click({
    $Error.Clear()
    $pbar.Value = 10
    $txtToken.Text = "Starting process..."
    Sleep-And-Update 300

    $dlfPath = $txtDLF.Text
    $cfgPath = $txtCFG.Text

    if ([string]::IsNullOrEmpty($dlfPath) -or -not (Test-Path $dlfPath)) {
        Show-Message "License file not found or path empty:`n$dlfPath" "Error" 'Error' -AlsoToToken
        $pbar.Value = 0
        return
    }
    $txtToken.Text = "License file found. Reading..."
    Sleep-And-Update 300

    if ($chkOverwrite.Checked) {
        if ([string]::IsNullOrWhiteSpace($cfgPath) -or -not (Test-Path $cfgPath)) {
            Show-Message "Config file not found or path empty:`n$cfgPath" "Error" 'Error' -AlsoToToken
            $pbar.Value = 0
            return
        }
    }
    $txtToken.Text = "Reading license file..."
    Sleep-And-Update 300

    $keyBytes = [byte[]](65,50,114,45,208,130,239,176,220,100,87,197,118,104,202,9)
    $iv = New-Object byte[] 16
    $bytes = [System.IO.File]::ReadAllBytes($dlfPath)
    $pbar.Value = 25
    $txtToken.Text = "Decrypting license file..."
    Sleep-And-Update 300

    $decryptedText = Try-Decrypt $bytes $keyBytes $iv

    if (-not $decryptedText) {
        if ($bytes.Length -le 0x41) {
            Show-Message "File too small for fallback decryption." "Error" "Error" -AlsoToToken
            $pbar.Value = 0
            return
        }
        $sliceLength = $bytes.Length - 0x41
        $bytes2 = New-Object byte[] $sliceLength
        [Array]::Copy($bytes, 0x41, $bytes2, 0, $sliceLength)
        $txtToken.Text = "Trying fallback decryption..."
        Sleep-And-Update 300
        $decryptedText = Try-Decrypt $bytes2 $keyBytes $iv
    }

    $pbar.Value = 41
    if (-not $decryptedText) {
        Show-Message "Decryption failed. Invalid/corrupt license file." "Error" "Error" -AlsoToToken
        $pbar.Value = 0
        return
    }
    $txtToken.Text = "Parsing decrypted XML..."
    Sleep-And-Update 300

    try { [xml]$xml = $decryptedText.Trim([char]0xFEFF) }
    catch {
        Show-Message "Decrypted data is not valid XML." "Error" "Error" -AlsoToToken
        $pbar.Value = 0
        return
    }
    $pbar.Value = 59

    $nsManager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $nsManager.AddNamespace("ns","http://ea.com/license")
    $tokenNode = $xml.SelectSingleNode("//ns:GameToken", $nsManager)
    if (-not $tokenNode) {
        Show-Message "GameToken not found in decrypted license." "Error" "Error" -AlsoToToken
        $pbar.Value = 0
        return
    }
    $txtToken.Text = "Extracting GameToken..."
    Sleep-And-Update 300

    $token = $tokenNode.InnerText -replace "\s+", ""
    $txtToken.Text = "Token extracted. Displaying..."
    Sleep-And-Update 300
    $pbar.Value = 75
    $txtToken.Text = $token

    if ($chkOverwrite.Checked) {
        $txtToken.Text += "`r`n`r`nBacking up config and updating..."
        Sleep-And-Update 300

        # Backup config
        $backup = "$cfgPath.bak"
        Copy-Item -Path $cfgPath -Destination $backup -Force

        # Update config logic
        $configText = Get-Content -Raw -LiteralPath $cfgPath
        $pattern = '("DenuvoToken"\s*"\s*)(.*?)(\s*")'
        $updatedText = [regex]::Replace($configText, $pattern,
            { param($m) $m.Groups[1].Value + $token + $m.Groups[3].Value },
            [System.Text.RegularExpressions.RegexOptions]::Singleline)

        if ($updatedText -eq $configText) {
            $updatedText += "`n`"DenuvoToken`" `"$token`""
        }
        Set-Content -LiteralPath $cfgPath -Value $updatedText -Encoding utf8

        $txtToken.Text += "`r`nUpdate completed successfully."
        # ✅ Success shown only in popup
        Show-Message "DenuvoToken updated!`nBackup created at:`n$backup" "Success" "Information"
    }else {
        Show-Message "DenuvoToken extracted successfully!" "Success" "Information"
    }

    $pbar.Value = 100
})

$form.Add_Shown({ $form.Activate() })
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
