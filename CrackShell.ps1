\
<#
CrackShell
Local OpenStego password recovery and hash comparison utility for Windows.

Run:
  powershell -ExecutionPolicy Bypass -File .\CrackShell.ps1

Place openstego.jar beside this script, or select it in the application.
Use only on files and hashes you own or are authorized to test.
#>

#region Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
#endregion

#region Global State
$scriptPath = $PSCommandPath
if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
if (-not $scriptPath) { $scriptPath = $MyInvocation.PSCommandPath }
if ($scriptPath) { $Script:AppDir = Split-Path -Parent $scriptPath }
else { $Script:AppDir = (Get-Location).Path }
if (-not $Script:AppDir) { $Script:AppDir = (Get-Location).Path }

$Script:DefaultJar = Join-Path $Script:AppDir 'openstego.jar'

$Script:StegoPS = $null
$Script:StegoAsync = $null
$Script:StegoShared = $null
$Script:StegoQueue = $null
$Script:StegoStartTime = $null

$Script:HashPS = $null
$Script:HashAsync = $null
$Script:HashShared = $null
$Script:HashQueue = $null
$Script:HashStartTime = $null

$Script:AESKey = $null
$Script:AESIV = $null
#endregion

#region General Helpers
function New-Label($text, $w = 120) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Width = $w
    $l.TextAlign = 'MiddleLeft'
    $l.AutoSize = $false
    return $l
}

function New-Button($text, $w = 110) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Width = $w
    $b.Height = 28
    return $b
}

function Set-ControlTreeTheme([System.Windows.Forms.Control]$root, [bool]$dark) {
    $bg = if ($dark) { [System.Drawing.Color]::Black } else { [System.Drawing.SystemColors]::Control }
    $fg = if ($dark) { [System.Drawing.Color]::Lime } else { [System.Drawing.SystemColors]::ControlText }
    $boxBg = if ($dark) { [System.Drawing.Color]::FromArgb(16,16,16) } else { [System.Drawing.SystemColors]::Window }
    $btnBg = if ($dark) { [System.Drawing.Color]::FromArgb(20,20,20) } else { [System.Drawing.SystemColors]::Control }

    $stack = New-Object System.Collections.Stack
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $c = $stack.Pop()
        foreach ($child in $c.Controls) { $stack.Push($child) }
        try {
            if ($c -is [System.Windows.Forms.TextBox] -or $c -is [System.Windows.Forms.RichTextBox] -or $c -is [System.Windows.Forms.DataGridView]) {
                $c.BackColor = $boxBg
                $c.ForeColor = $fg
            } elseif ($c -is [System.Windows.Forms.Button]) {
                $c.BackColor = $btnBg
                $c.ForeColor = $fg
                $c.FlatStyle = if ($dark) { 'Flat' } else { 'Standard' }
                if ($dark) { $c.FlatAppearance.BorderColor = $fg }
            } else {
                $c.BackColor = $bg
                $c.ForeColor = $fg
            }

            if ($c -is [System.Windows.Forms.ComboBox]) {
                $c.BackColor = $boxBg
                $c.ForeColor = $fg
                $c.FlatStyle = if ($dark) { 'Flat' } else { 'Standard' }
            }

            if ($c -is [System.Windows.Forms.DataGridView]) {
                $c.EnableHeadersVisualStyles = -not $dark
                $c.BackgroundColor = $boxBg
                $c.GridColor = if ($dark) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.SystemColors]::ControlDark }
                if ($dark) {
                    $c.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Black
                    $c.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Lime
                    $c.DefaultCellStyle.BackColor = $boxBg
                    $c.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Lime
                    $c.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(32,96,32)
                    $c.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
                }
            }
        } catch {}
    }
}

function Add-FilePickerRow($parent, $row, $labelText, $textBox, $button, [bool]$folderPicker, $filter) {
    $parent.Controls.Add((New-Label $labelText 110), 0, $row)
    $parent.Controls.Add($textBox, 1, $row)
    $parent.SetColumnSpan($textBox, 4)
    $parent.Controls.Add($button, 5, $row)
    $button.Add_Click({
        if ($folderPicker) {
            $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
            if ($dlg.ShowDialog() -eq 'OK') { $textBox.Text = $dlg.SelectedPath }
        } else {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Filter = $filter
            if ($dlg.ShowDialog() -eq 'OK') { $textBox.Text = $dlg.FileName }
        }
    }.GetNewClosure())
}

function Get-StringDistance([string]$A,[string]$B){
    if ($null -eq $A) { $A = '' }
    if ($null -eq $B) { $B = '' }
    $len = [Math]::Min($A.Length,$B.Length)
    $d=0
    for($i=0;$i -lt $len;$i++){ if($A[$i] -ne $B[$i]){$d++} }
    return $d + [Math]::Abs($A.Length-$B.Length)
}
#endregion

#region Crypto Helpers
function New-AesMaterial([int]$KeySize){
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = $KeySize
    $aes.GenerateKey()
    $aes.GenerateIV()
    $Script:AESKey = $aes.Key
    $Script:AESIV = $aes.IV
    $aes.Dispose()
}

function Ensure-AesMaterial([int]$KeySize){
    if (-not $Script:AESKey -or -not $Script:AESIV -or (($Script:AESKey.Length * 8) -ne $KeySize)) {
        New-AesMaterial $KeySize
    }
}

function Apply-SaltLocal([string]$s, [string]$saltText, [string]$saltMode){
    switch ($saltMode) {
        'Prefix' { return ($saltText + $s) }
        'Suffix' { return ($s + $saltText) }
        default { return $s }
    }
}
#endregion

#region Form Shell
$fontMain = New-Object System.Drawing.Font('Segoe UI', 9)
$fontMono = New-Object System.Drawing.Font('Consolas', 9)

$form = New-Object System.Windows.Forms.Form
$form.Text = 'CrackShell'
$form.Size = New-Object System.Drawing.Size(1250, 820)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 720)
$form.StartPosition = 'CenterScreen'
$form.Font = $fontMain

$menu = New-Object System.Windows.Forms.MenuStrip
$mView = New-Object System.Windows.Forms.ToolStripMenuItem('View')
$mDark = New-Object System.Windows.Forms.ToolStripMenuItem('Dark Mode')
$mDark.CheckOnClick = $true
$mView.DropDownItems.Add($mDark) | Out-Null
$mHelp = New-Object System.Windows.Forms.ToolStripMenuItem('Help')
$mAbout = New-Object System.Windows.Forms.ToolStripMenuItem('About')
$mHelp.DropDownItems.Add($mAbout) | Out-Null
$menu.Items.AddRange(@($mView, $mHelp))
$form.Controls.Add($menu)
$form.MainMenuStrip = $menu

$status = New-Object System.Windows.Forms.StatusStrip
$stMain = New-Object System.Windows.Forms.ToolStripStatusLabel
$stMain.Text = 'Ready'
$status.Items.Add($stMain) | Out-Null
$form.Controls.Add($status)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Padding = New-Object System.Drawing.Point(18, 6)
$form.Controls.Add($tabs)
$tabs.BringToFront()

$tabStego = New-Object System.Windows.Forms.TabPage
$tabStego.Text = 'OpenStego Cracker'
$tabHash = New-Object System.Windows.Forms.TabPage
$tabHash.Text = 'Hash Solver'
$tabs.TabPages.AddRange(@($tabStego, $tabHash))
#endregion

#region OpenStego Tab
$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = 'Fill'
$main.RowCount = 4
$main.ColumnCount = 1
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 180)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 70)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 165)))
$tabStego.Controls.Add($main)

$grpFiles = New-Object System.Windows.Forms.GroupBox
$grpFiles.Text = 'Files'
$grpFiles.Dock = 'Fill'
$main.Controls.Add($grpFiles, 0, 0)

$fileGrid = New-Object System.Windows.Forms.TableLayoutPanel
$fileGrid.Dock = 'Fill'
$fileGrid.ColumnCount = 6
$fileGrid.RowCount = 4
$fileGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
for ($i = 1; $i -lt 5; $i++) { $fileGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 25))) }
$fileGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
$grpFiles.Controls.Add($fileGrid)

$txtJar = New-Object System.Windows.Forms.TextBox; $txtJar.Dock = 'Fill'
$txtImage = New-Object System.Windows.Forms.TextBox; $txtImage.Dock = 'Fill'
$txtWordlist = New-Object System.Windows.Forms.TextBox; $txtWordlist.Dock = 'Fill'
$txtOutputDir = New-Object System.Windows.Forms.TextBox; $txtOutputDir.Dock = 'Fill'
if (Test-Path $Script:DefaultJar) { $txtJar.Text = $Script:DefaultJar }

$btnJar = New-Button 'Browse...'
$btnImage = New-Button 'Browse...'
$btnWordlist = New-Button 'Browse...'
$btnOut = New-Button 'Browse...'
Add-FilePickerRow $fileGrid 0 'OpenStego JAR:' $txtJar $btnJar $false 'JAR files (*.jar)|*.jar|All files (*.*)|*.*'
Add-FilePickerRow $fileGrid 1 'Stego Image:' $txtImage $btnImage $false 'Image files|*.png;*.jpg;*.jpeg;*.bmp;*.gif|All files (*.*)|*.*'
Add-FilePickerRow $fileGrid 2 'Wordlist:' $txtWordlist $btnWordlist $false 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
Add-FilePickerRow $fileGrid 3 'Output Folder:' $txtOutputDir $btnOut $true ''

$grpControls = New-Object System.Windows.Forms.GroupBox
$grpControls.Text = 'Controls'
$grpControls.Dock = 'Fill'
$main.Controls.Add($grpControls, 0, 1)

$flow = New-Object System.Windows.Forms.FlowLayoutPanel
$flow.Dock = 'Fill'
$flow.Padding = New-Object System.Windows.Forms.Padding(8)
$grpControls.Controls.Add($flow)
$btnStart = New-Button 'Start Cracking' 130
$btnPause = New-Button 'Pause' 90
$btnCancel = New-Button 'Cancel' 90
$btnPause.Enabled = $false
$btnCancel.Enabled = $false
$lblProgress = New-Label 'Progress: 0%' 120
$lblElapsed = New-Label 'Elapsed: 00:00:00' 150
$txtCurrent = New-Object System.Windows.Forms.TextBox; $txtCurrent.Width = 260; $txtCurrent.ReadOnly = $true
$txtFound = New-Object System.Windows.Forms.TextBox; $txtFound.Width = 220; $txtFound.ReadOnly = $true
$flow.Controls.AddRange(@($btnStart, $btnPause, $btnCancel, (New-Label 'Current:' 55), $txtCurrent, (New-Label 'Found:' 45), $txtFound, $lblProgress, $lblElapsed))

$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = 'Output Log'
$grpLog.Dock = 'Fill'
$main.Controls.Add($grpLog, 0, 2)
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$txtLog.Dock = 'Fill'
$txtLog.Font = $fontMono
$grpLog.Controls.Add($txtLog)

$bottom = New-Object System.Windows.Forms.TableLayoutPanel
$bottom.Dock = 'Fill'
$bottom.ColumnCount = 2
$bottom.RowCount = 1
$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 70)))
$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 30)))
$main.Controls.Add($bottom, 0, 3)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock = 'Top'
$progress.Height = 22
$progress.Minimum = 0
$progress.Maximum = 100
$bottom.Controls.Add($progress, 0, 0)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'Fill'
[void]$grid.Columns.Add('When', 'When')
[void]$grid.Columns.Add('Image', 'Image')
[void]$grid.Columns.Add('Wordlist', 'Wordlist')
[void]$grid.Columns.Add('Password', 'Password')
[void]$grid.Columns.Add('Status', 'Status')
$bottom.Controls.Add($grid, 1, 0)
#endregion

#region Hash Solver Tab
$hashMain = New-Object System.Windows.Forms.TableLayoutPanel
$hashMain.Dock = 'Fill'
$hashMain.RowCount = 5
$hashMain.ColumnCount = 1
$hashMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 145)))
$hashMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 110)))
$hashMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 70)))
$hashMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$hashMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 165)))
$tabHash.Controls.Add($hashMain)

$grpHashAlgo = New-Object System.Windows.Forms.GroupBox
$grpHashAlgo.Text = 'Algorithm and Options'
$grpHashAlgo.Dock = 'Fill'
$hashMain.Controls.Add($grpHashAlgo, 0, 0)

$algoGrid = New-Object System.Windows.Forms.TableLayoutPanel
$algoGrid.Dock = 'Fill'
$algoGrid.ColumnCount = 10
$algoGrid.RowCount = 3
for ($i=0; $i -lt 10; $i++) { $algoGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,10))) }
$grpHashAlgo.Controls.Add($algoGrid)

$comboAlgo = New-Object System.Windows.Forms.ComboBox
$comboAlgo.DropDownStyle = 'DropDownList'
$comboAlgo.Items.AddRange(@('MD5','SHA1','SHA256','SHA384','SHA512','AES'))
$comboAlgo.SelectedItem = 'SHA256'
$comboAlgo.Dock = 'Fill'

$comboKey = New-Object System.Windows.Forms.ComboBox
$comboKey.DropDownStyle = 'DropDownList'
$comboKey.Items.AddRange(@('128','192','256'))
$comboKey.SelectedItem = '128'
$comboKey.Enabled = $false
$comboKey.Dock = 'Fill'

$comboMode = New-Object System.Windows.Forms.ComboBox
$comboMode.DropDownStyle = 'DropDownList'
$comboMode.Items.AddRange(@('CBC','ECB','CFB','OFB'))
$comboMode.SelectedItem = 'CBC'
$comboMode.Enabled = $false
$comboMode.Dock = 'Fill'

$btnRegenAES = New-Button 'Regenerate' 105
$btnRegenAES.Enabled = $false
$txtAESKey = New-Object System.Windows.Forms.TextBox; $txtAESKey.ReadOnly = $true; $txtAESKey.Dock = 'Fill'
$txtAESIV = New-Object System.Windows.Forms.TextBox; $txtAESIV.ReadOnly = $true; $txtAESIV.Dock = 'Fill'
$txtCustomKey = New-Object System.Windows.Forms.TextBox; $txtCustomKey.Dock = 'Fill'
$txtCustomIV = New-Object System.Windows.Forms.TextBox; $txtCustomIV.Dock = 'Fill'
$btnApplyAES = New-Button 'Apply AES' 100
$btnApplyAES.Enabled = $false
$txtSalt = New-Object System.Windows.Forms.TextBox; $txtSalt.Dock = 'Fill'
$comboSaltMode = New-Object System.Windows.Forms.ComboBox
$comboSaltMode.DropDownStyle = 'DropDownList'
$comboSaltMode.Items.AddRange(@('None','Prefix','Suffix'))
$comboSaltMode.SelectedItem = 'None'
$comboSaltMode.Dock = 'Fill'

$algoGrid.Controls.Add((New-Label 'Algorithm:' 80),0,0); $algoGrid.Controls.Add($comboAlgo,1,0)
$algoGrid.Controls.Add((New-Label 'AES Key:' 70),2,0); $algoGrid.Controls.Add($comboKey,3,0)
$algoGrid.Controls.Add((New-Label 'Mode:' 50),4,0); $algoGrid.Controls.Add($comboMode,5,0)
$algoGrid.Controls.Add($btnRegenAES,6,0)
$algoGrid.Controls.Add((New-Label 'Salt:' 45),7,0); $algoGrid.Controls.Add($txtSalt,8,0); $algoGrid.Controls.Add($comboSaltMode,9,0)

$algoGrid.Controls.Add((New-Label 'Key B64:' 80),0,1); $algoGrid.Controls.Add($txtAESKey,1,1); $algoGrid.SetColumnSpan($txtAESKey,4)
$algoGrid.Controls.Add((New-Label 'IV B64:' 70),5,1); $algoGrid.Controls.Add($txtAESIV,6,1); $algoGrid.SetColumnSpan($txtAESIV,4)

$algoGrid.Controls.Add((New-Label 'Custom Key:' 80),0,2); $algoGrid.Controls.Add($txtCustomKey,1,2); $algoGrid.SetColumnSpan($txtCustomKey,4)
$algoGrid.Controls.Add((New-Label 'Custom IV:' 70),5,2); $algoGrid.Controls.Add($txtCustomIV,6,2); $algoGrid.SetColumnSpan($txtCustomIV,3)
$algoGrid.Controls.Add($btnApplyAES,9,2)

$grpHashTarget = New-Object System.Windows.Forms.GroupBox
$grpHashTarget.Text = 'Target and Wordlist'
$grpHashTarget.Dock = 'Fill'
$hashMain.Controls.Add($grpHashTarget, 0, 1)

$hashTargetGrid = New-Object System.Windows.Forms.TableLayoutPanel
$hashTargetGrid.Dock = 'Fill'
$hashTargetGrid.ColumnCount = 6
$hashTargetGrid.RowCount = 3
$hashTargetGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
for ($i=1; $i -lt 5; $i++) { $hashTargetGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,25))) }
$hashTargetGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
$grpHashTarget.Controls.Add($hashTargetGrid)

$txtTargetHash = New-Object System.Windows.Forms.TextBox; $txtTargetHash.Dock='Fill'
$txtHashWordlist = New-Object System.Windows.Forms.TextBox; $txtHashWordlist.Dock='Fill'
$btnHashWordlist = New-Button 'Browse...'
$btnHashUseStegoWordlist = New-Button 'Use Stego WL' 110
$hashTargetGrid.Controls.Add((New-Label 'Target Hash:' 110),0,0)
$hashTargetGrid.Controls.Add($txtTargetHash,1,0); $hashTargetGrid.SetColumnSpan($txtTargetHash,5)
Add-FilePickerRow $hashTargetGrid 1 'Wordlist:' $txtHashWordlist $btnHashWordlist $false 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
$hashTargetGrid.Controls.Add((New-Label 'Shortcut:' 110),0,2)
$hashTargetGrid.Controls.Add($btnHashUseStegoWordlist,1,2)

$grpHashControls = New-Object System.Windows.Forms.GroupBox
$grpHashControls.Text = 'Controls'
$grpHashControls.Dock = 'Fill'
$hashMain.Controls.Add($grpHashControls, 0, 2)
$hashFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$hashFlow.Dock = 'Fill'
$hashFlow.Padding = New-Object System.Windows.Forms.Padding(8)
$grpHashControls.Controls.Add($hashFlow)
$btnHashStart = New-Button 'Start Solver' 120
$btnHashPause = New-Button 'Pause' 90
$btnHashCancel = New-Button 'Cancel' 90
$btnHashPause.Enabled = $false
$btnHashCancel.Enabled = $false
$lblHashProgress = New-Label 'Progress: 0%' 120
$lblHashElapsed = New-Label 'Elapsed: 00:00:00' 150
$txtHashCurrent = New-Object System.Windows.Forms.TextBox; $txtHashCurrent.Width = 240; $txtHashCurrent.ReadOnly = $true
$txtHashFound = New-Object System.Windows.Forms.TextBox; $txtHashFound.Width = 220; $txtHashFound.ReadOnly = $true
$txtHashBestDist = New-Object System.Windows.Forms.TextBox; $txtHashBestDist.Width = 70; $txtHashBestDist.ReadOnly = $true
$hashFlow.Controls.AddRange(@($btnHashStart,$btnHashPause,$btnHashCancel,(New-Label 'Current:' 55),$txtHashCurrent,(New-Label 'Found:' 45),$txtHashFound,(New-Label 'Best Dist:' 65),$txtHashBestDist,$lblHashProgress,$lblHashElapsed))

$grpHashLog = New-Object System.Windows.Forms.GroupBox
$grpHashLog.Text = 'Hash Solver Log'
$grpHashLog.Dock = 'Fill'
$hashMain.Controls.Add($grpHashLog,0,3)
$txtHashLog = New-Object System.Windows.Forms.TextBox
$txtHashLog.Multiline = $true
$txtHashLog.ScrollBars = 'Vertical'
$txtHashLog.ReadOnly = $true
$txtHashLog.Dock = 'Fill'
$txtHashLog.Font = $fontMono
$grpHashLog.Controls.Add($txtHashLog)

$hashBottom = New-Object System.Windows.Forms.TableLayoutPanel
$hashBottom.Dock = 'Fill'
$hashBottom.ColumnCount = 2
$hashBottom.RowCount = 1
$hashBottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,70)))
$hashBottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,30)))
$hashMain.Controls.Add($hashBottom,0,4)

$hashProgress = New-Object System.Windows.Forms.ProgressBar
$hashProgress.Dock = 'Top'
$hashProgress.Height = 22
$hashProgress.Minimum = 0
$hashProgress.Maximum = 100
$hashBottom.Controls.Add($hashProgress,0,0)

$hashGrid = New-Object System.Windows.Forms.DataGridView
$hashGrid.Dock = 'Fill'
$hashGrid.ReadOnly = $true
$hashGrid.AllowUserToAddRows = $false
$hashGrid.AllowUserToDeleteRows = $false
$hashGrid.RowHeadersVisible = $false
$hashGrid.SelectionMode = 'FullRowSelect'
$hashGrid.AutoSizeColumnsMode = 'Fill'
[void]$hashGrid.Columns.Add('When','When')
[void]$hashGrid.Columns.Add('Algo','Algo')
[void]$hashGrid.Columns.Add('Wordlist','Wordlist')
[void]$hashGrid.Columns.Add('Password','Password')
[void]$hashGrid.Columns.Add('Status','Status')
$hashBottom.Controls.Add($hashGrid,1,0)
#endregion

#region UI Log and Reset Helpers
function Write-StegoLog([string]$message) {
    $txtLog.AppendText($message + [Environment]::NewLine)
    $txtLog.SelectionStart = $txtLog.Text.Length
    $txtLog.ScrollToCaret()
}

function Write-HashLog([string]$message) {
    $txtHashLog.AppendText($message + [Environment]::NewLine)
    $txtHashLog.SelectionStart = $txtHashLog.Text.Length
    $txtHashLog.ScrollToCaret()
}

function Reset-StegoUi {
    $btnStart.Enabled = $true
    $btnPause.Enabled = $false
    $btnCancel.Enabled = $false
    $btnPause.Text = 'Pause'
    $progress.Value = 0
    $lblProgress.Text = 'Progress: 0%'
    $lblElapsed.Text = 'Elapsed: 00:00:00'
}

function Reset-HashUi {
    $btnHashStart.Enabled = $true
    $btnHashPause.Enabled = $false
    $btnHashCancel.Enabled = $false
    $btnHashPause.Text = 'Pause'
    $hashProgress.Value = 0
    $lblHashProgress.Text = 'Progress: 0%'
    $lblHashElapsed.Text = 'Elapsed: 00:00:00'
}

function Stop-StegoWorker {
    if ($Script:StegoShared) { $Script:StegoShared.Cancel = $true }
    if ($Script:StegoPS) {
        try { $Script:StegoPS.Stop() } catch {}
        try { $Script:StegoPS.Dispose() } catch {}
    }
    $Script:StegoPS = $null
    $Script:StegoAsync = $null
}

function Stop-HashWorker {
    if ($Script:HashShared) { $Script:HashShared.Cancel = $true }
    if ($Script:HashPS) {
        try { $Script:HashPS.Stop() } catch {}
        try { $Script:HashPS.Dispose() } catch {}
    }
    $Script:HashPS = $null
    $Script:HashAsync = $null
}
#endregion

#region Worker Scripts
$stegoScript = {
    param($jarPath, $imagePath, $wordlistPath, $outputDir, $shared, $queue)
    function PushLog($s) { $queue.Enqueue([string]$s) }
    $shared.Running = $true
    $shared.Status = 'Starting'
    $shared.FoundPassword = ''
    $shared.Current = ''
    $shared.Index = 0
    $shared.Total = 0
    try {
        if (-not (Test-Path $jarPath)) { throw "OpenStego JAR not found: $jarPath" }
        if (-not (Test-Path $imagePath)) { throw "Image not found: $imagePath" }
        if (-not (Test-Path $wordlistPath)) { throw "Wordlist not found: $wordlistPath" }
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
        $javaCheck = & java -version 2>&1
        if ($LASTEXITCODE -ne 0 -and -not $javaCheck) { throw 'Java was not found. Install Java or add java.exe to PATH.' }
        $passwords = [System.IO.File]::ReadLines($wordlistPath)
        $total = 0
        foreach ($p in [System.IO.File]::ReadLines($wordlistPath)) { $total++ }
        $shared.Total = $total
        PushLog ''
        PushLog ('=' * 60)
        PushLog 'Starting OpenStego cracking process'
        PushLog "Image: $imagePath"
        PushLog "Wordlist: $wordlistPath"
        PushLog "Output: $outputDir"
        PushLog "Passwords loaded: $total"
        PushLog ('=' * 60)
        $i = 0
        foreach ($raw in $passwords) {
            if ($shared.Cancel) { $shared.Status = 'Cancelled'; PushLog 'Cracking cancelled.'; break }
            while ($shared.Pause -and -not $shared.Cancel) { $shared.Status = 'Paused'; Start-Sleep -Milliseconds 150 }
            $password = ([string]$raw).Trim()
            $i++; $shared.Index = $i
            if ([string]::IsNullOrWhiteSpace($password)) { continue }
            $shared.Current = $password
            $shared.Status = "Trying $i of $total"
            PushLog "[$i/$total] Trying password: '$password'"
            $before = @{}
            Get-ChildItem -LiteralPath $outputDir -File -ErrorAction SilentlyContinue | ForEach-Object { $before[$_.FullName] = $true }
            $args = @('-jar', $jarPath, 'extract', '-p', $password, '-sf', $imagePath, '-xd', $outputDir)
            $output = & java @args 2>&1
            $exitCode = $LASTEXITCODE
            $joined = ($output | Out-String)
            $after = Get-ChildItem -LiteralPath $outputDir -File -ErrorAction SilentlyContinue
            $newFiles = @($after | Where-Object { -not $before.ContainsKey($_.FullName) })
            if ($newFiles.Count -gt 0 -and $joined -notmatch 'InvalidPasswordException') {
                $shared.FoundPassword = $password
                $shared.Status = 'Password found'
                PushLog ''
                PushLog ('*' * 30)
                PushLog "SUCCESS. Password found: $password"
                foreach ($file in $newFiles) {
                    PushLog "Extracted: $($file.FullName)"
                    try {
                        $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                        if ($content.Length -gt 1500) { $content = $content.Substring(0,1500) + "`r`n...content truncated..." }
                        PushLog "--- Content preview: $($file.Name) ---"
                        PushLog $content
                        PushLog '--- End preview ---'
                    } catch { PushLog "Could not preview $($file.Name): $($_.Exception.Message)" }
                }
                PushLog ('*' * 30)
                break
            } elseif ($joined -match 'InvalidPasswordException') {
                PushLog '  -> Incorrect password.'
            } elseif ($exitCode -ne 0 -or $joined -match 'Exception|Error') {
                $short = ($joined.Trim() -replace "`r?`n", ' ')
                if ($short.Length -gt 250) { $short = $short.Substring(0,250) + '...' }
                PushLog ('  -> OpenStego message: ' + $short)
            } else { PushLog '  -> No new file created.' }
        }
        if (-not $shared.FoundPassword -and -not $shared.Cancel) { $shared.Status = 'Finished, not found'; PushLog ''; PushLog 'Finished. Password was not found in the wordlist.' }
    } catch { $shared.Status = 'Error'; PushLog "ERROR: $($_.Exception.Message)" }
    finally { $shared.Running = $false }
}

$hashScript = {
    param($algo, $target, $wordlistPath, $saltText, $saltMode, $keySize, $mode, $keyB64, $ivB64, $shared, $queue)
    function PushLog($s) { $queue.Enqueue([string]$s) }
    function Apply-Salt([string]$s, [string]$saltText, [string]$saltMode){
        switch ($saltMode) {
            'Prefix' { return ($saltText + $s) }
            'Suffix' { return ($s + $saltText) }
            default { return $s }
        }
    }
    function Distance([string]$A,[string]$B){
        if ($null -eq $A) { $A = '' }
        if ($null -eq $B) { $B = '' }
        $len = [Math]::Min($A.Length,$B.Length)
        $d=0
        for($i=0;$i -lt $len;$i++){ if($A[$i] -ne $B[$i]){$d++} }
        return $d + [Math]::Abs($A.Length-$B.Length)
    }
    $shared.Running = $true
    $shared.Status = 'Starting'
    $shared.FoundPassword = ''
    $shared.Current = ''
    $shared.CurrentValue = ''
    $shared.BestWord = ''
    $shared.BestValue = ''
    $shared.BestDistance = [int]::MaxValue
    $shared.Index = 0
    $shared.Total = 0
    try {
        if (-not (Test-Path $wordlistPath)) { throw "Wordlist not found: $wordlistPath" }
        if ([string]::IsNullOrWhiteSpace($target)) { throw 'Target hash/value is empty.' }
        if ($algo -eq 'AES') {
            if ([string]::IsNullOrWhiteSpace($keyB64) -or [string]::IsNullOrWhiteSpace($ivB64)) { throw 'AES needs a Key and IV.' }
            $aesKey = [Convert]::FromBase64String($keyB64)
            $aesIV = [Convert]::FromBase64String($ivB64)
        }
        $total = 0
        foreach ($p in [System.IO.File]::ReadLines($wordlistPath)) { $total++ }
        $shared.Total = $total
        PushLog ''
        PushLog ('=' * 60)
        PushLog "Starting hash solver"
        PushLog "Algorithm: $algo"
        if ($algo -eq 'AES') { PushLog "AES: $keySize/$mode" }
        PushLog "Salt mode: $saltMode"
        PushLog "Wordlist: $wordlistPath"
        PushLog "Candidates loaded: $total"
        PushLog ('=' * 60)
        $targetCompare = if ($algo -eq 'AES') { $target.Trim() } else { $target.Trim().ToUpperInvariant() }
        $i = 0
        foreach ($raw in [System.IO.File]::ReadLines($wordlistPath)) {
            if ($shared.Cancel) { $shared.Status = 'Cancelled'; PushLog 'Solver cancelled.'; break }
            while ($shared.Pause -and -not $shared.Cancel) { $shared.Status = 'Paused'; Start-Sleep -Milliseconds 150 }
            $word = ([string]$raw).Trim()
            $i++; $shared.Index = $i
            if ([string]::IsNullOrWhiteSpace($word)) { continue }
            $shared.Current = $word
            $candidate = Apply-Salt $word $saltText $saltMode
            if ($algo -eq 'AES') {
                $aes = [System.Security.Cryptography.Aes]::Create()
                $aes.KeySize = [int]$keySize
                $aes.Mode = [System.Enum]::Parse([System.Security.Cryptography.CipherMode], $mode)
                $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $aes.Key = $aesKey
                $aes.IV = $aesIV
                $enc = $aes.CreateEncryptor()
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($candidate)
                    $cipherBytes = $enc.TransformFinalBlock($bytes,0,$bytes.Length)
                    $value = [Convert]::ToBase64String($cipherBytes)
                } finally { $enc.Dispose(); $aes.Dispose() }
                $valueCompare = $value
            } else {
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($algo)
                if (-not $hasher) { throw "Algorithm $algo not available under system policy." }
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($candidate)
                    $value = ([BitConverter]::ToString($hasher.ComputeHash($bytes)) -replace '-','')
                } finally { $hasher.Dispose() }
                $valueCompare = $value.ToUpperInvariant()
            }
            $shared.CurrentValue = $value
            $d = Distance $targetCompare $valueCompare
            if ($d -lt $shared.BestDistance) {
                $shared.BestDistance = $d
                $shared.BestWord = $word
                $shared.BestValue = $value
                PushLog "[$i/$total] New best distance $d -> '$word'"
            }
            $shared.Status = "Trying $i of $total"
            if ($valueCompare -eq $targetCompare) {
                $shared.FoundPassword = $word
                $shared.Status = 'Password found'
                PushLog ''
                PushLog ('*' * 30)
                PushLog "SUCCESS. Match found: $word"
                PushLog "Value: $value"
                PushLog ('*' * 30)
                break
            }
        }
        if (-not $shared.FoundPassword -and -not $shared.Cancel) { $shared.Status = 'Finished, not found'; PushLog ''; PushLog 'Finished. No exact match was found.'; PushLog "Best candidate: $($shared.BestWord)"; PushLog "Best distance: $($shared.BestDistance)"; PushLog "Best value: $($shared.BestValue)" }
    } catch { $shared.Status = 'Error'; PushLog "ERROR: $($_.Exception.Message)" }
    finally { $shared.Running = $false }
}
#endregion

#region Timers
$stegoTimer = New-Object System.Windows.Forms.Timer
$stegoTimer.Interval = 100
$stegoTimer.Add_Tick({
    if ($Script:StegoQueue) {
        $msg = $null
        while ($Script:StegoQueue.TryDequeue([ref]$msg)) { Write-StegoLog $msg }
    }
    if ($Script:StegoShared) {
        $txtCurrent.Text = [string]$Script:StegoShared.Current
        $txtFound.Text = [string]$Script:StegoShared.FoundPassword
        if ($Script:StegoShared.Total -gt 0) {
            $pct = [int][Math]::Round(([double]$Script:StegoShared.Index / [double]$Script:StegoShared.Total) * 100)
            $pct = [Math]::Max(0, [Math]::Min(100, $pct))
            $progress.Value = $pct
            $lblProgress.Text = "Progress: $pct%"
        }
        if ($Script:StegoStartTime) { $lblElapsed.Text = 'Elapsed: ' + ((Get-Date) - $Script:StegoStartTime).ToString('hh\:mm\:ss') }
        $stMain.Text = [string]$Script:StegoShared.Status
        if (-not $Script:StegoShared.Running -and $Script:StegoPS) {
            try { $Script:StegoPS.EndInvoke($Script:StegoAsync) } catch {}
            try { $Script:StegoPS.Dispose() } catch {}
            $Script:StegoPS = $null; $Script:StegoAsync = $null
            $stegoTimer.Stop()
            $statusText = if ($Script:StegoShared.FoundPassword) { 'Found' } elseif ($Script:StegoShared.Cancel) { 'Cancelled' } else { [string]$Script:StegoShared.Status }
            [void]$grid.Rows.Add((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), [IO.Path]::GetFileName($txtImage.Text), [IO.Path]::GetFileName($txtWordlist.Text), [string]$Script:StegoShared.FoundPassword, $statusText)
            Reset-StegoUi
        }
    }
})

$hashTimer = New-Object System.Windows.Forms.Timer
$hashTimer.Interval = 100
$hashTimer.Add_Tick({
    if ($Script:HashQueue) {
        $msg = $null
        while ($Script:HashQueue.TryDequeue([ref]$msg)) { Write-HashLog $msg }
    }
    if ($Script:HashShared) {
        $txtHashCurrent.Text = [string]$Script:HashShared.Current
        $txtHashFound.Text = [string]$Script:HashShared.FoundPassword
        $txtHashBestDist.Text = if ($Script:HashShared.BestDistance -eq [int]::MaxValue) { '' } else { [string]$Script:HashShared.BestDistance }
        if ($Script:HashShared.Total -gt 0) {
            $pct = [int][Math]::Round(([double]$Script:HashShared.Index / [double]$Script:HashShared.Total) * 100)
            $pct = [Math]::Max(0, [Math]::Min(100, $pct))
            $hashProgress.Value = $pct
            $lblHashProgress.Text = "Progress: $pct%"
        }
        if ($Script:HashStartTime) { $lblHashElapsed.Text = 'Elapsed: ' + ((Get-Date) - $Script:HashStartTime).ToString('hh\:mm\:ss') }
        $stMain.Text = [string]$Script:HashShared.Status
        if (-not $Script:HashShared.Running -and $Script:HashPS) {
            try { $Script:HashPS.EndInvoke($Script:HashAsync) } catch {}
            try { $Script:HashPS.Dispose() } catch {}
            $Script:HashPS = $null; $Script:HashAsync = $null
            $hashTimer.Stop()
            $statusText = if ($Script:HashShared.FoundPassword) { 'Found' } elseif ($Script:HashShared.Cancel) { 'Cancelled' } else { [string]$Script:HashShared.Status }
            [void]$hashGrid.Rows.Add((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), [string]$comboAlgo.SelectedItem, [IO.Path]::GetFileName($txtHashWordlist.Text), [string]$Script:HashShared.FoundPassword, $statusText)
            Reset-HashUi
        }
    }
})
#endregion

#region Events
$mDark.Add_CheckedChanged({ Set-ControlTreeTheme $form $mDark.Checked })
$mAbout.Add_Click({
    [System.Windows.Forms.MessageBox]::Show("CrackShell`r`nLocal OpenStego password recovery and hash comparison tools.", 'About', 'OK', 'Information') | Out-Null
})

$comboAlgo.Add_SelectedIndexChanged({
    $useAES = ($comboAlgo.SelectedItem -eq 'AES')
    $comboKey.Enabled = $useAES
    $comboMode.Enabled = $useAES
    $btnRegenAES.Enabled = $useAES
    $btnApplyAES.Enabled = $useAES
})

$comboKey.Add_SelectedIndexChanged({
    New-AesMaterial ([int]$comboKey.SelectedItem)
    $txtAESKey.Text = [Convert]::ToBase64String($Script:AESKey)
    $txtAESIV.Text = [Convert]::ToBase64String($Script:AESIV)
})

$btnRegenAES.Add_Click({
    New-AesMaterial ([int]$comboKey.SelectedItem)
    $txtAESKey.Text = [Convert]::ToBase64String($Script:AESKey)
    $txtAESIV.Text = [Convert]::ToBase64String($Script:AESIV)
    Write-HashLog 'AES key and IV regenerated.'
})

$btnApplyAES.Add_Click({
    try {
        if ($txtCustomKey.Text.Trim()) { $Script:AESKey = [Convert]::FromBase64String($txtCustomKey.Text.Trim()) }
        if ($txtCustomIV.Text.Trim()) { $Script:AESIV = [Convert]::FromBase64String($txtCustomIV.Text.Trim()) }
        $txtAESKey.Text = [Convert]::ToBase64String($Script:AESKey)
        $txtAESIV.Text = [Convert]::ToBase64String($Script:AESIV)
        Write-HashLog 'Custom AES key and IV applied.'
    } catch { Write-HashLog "Invalid AES Key/IV. Expected Base64. $($_.Exception.Message)" }
})

$btnHashUseStegoWordlist.Add_Click({
    if ($txtWordlist.Text.Trim()) { $txtHashWordlist.Text = $txtWordlist.Text.Trim() }
})

$btnStart.Add_Click({
    if ($Script:StegoPS) { return }
    if (-not $txtJar.Text.Trim() -or -not $txtImage.Text.Trim() -or -not $txtWordlist.Text.Trim() -or -not $txtOutputDir.Text.Trim()) {
        [System.Windows.Forms.MessageBox]::Show('Select the OpenStego JAR, image, wordlist, and output folder first.', 'Missing Information', 'OK', 'Warning') | Out-Null
        return
    }
    $Script:StegoQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    $Script:StegoShared = [hashtable]::Synchronized(@{ Cancel=$false; Pause=$false; Running=$false; Status='Queued'; Current=''; FoundPassword=''; Index=0; Total=0 })
    $txtLog.Clear(); $txtCurrent.Clear(); $txtFound.Clear()
    $btnStart.Enabled = $false; $btnPause.Enabled = $true; $btnCancel.Enabled = $true
    $progress.Value = 0
    $Script:StegoStartTime = Get-Date
    $Script:StegoPS = [PowerShell]::Create()
    [void]$Script:StegoPS.AddScript($stegoScript).AddArgument($txtJar.Text.Trim()).AddArgument($txtImage.Text.Trim()).AddArgument($txtWordlist.Text.Trim()).AddArgument($txtOutputDir.Text.Trim()).AddArgument($Script:StegoShared).AddArgument($Script:StegoQueue)
    $Script:StegoAsync = $Script:StegoPS.BeginInvoke()
    $stegoTimer.Start()
})

$btnPause.Add_Click({
    if (-not $Script:StegoShared) { return }
    $Script:StegoShared.Pause = -not $Script:StegoShared.Pause
    $btnPause.Text = if ($Script:StegoShared.Pause) { 'Resume' } else { 'Pause' }
})

$btnCancel.Add_Click({
    if ($Script:StegoShared) { $Script:StegoShared.Cancel = $true }
    Write-StegoLog 'Cancel requested. Waiting for current Java attempt to finish.'
})

$btnHashStart.Add_Click({
    if ($Script:HashPS) { return }
    if (-not $txtTargetHash.Text.Trim() -or -not $txtHashWordlist.Text.Trim()) {
        [System.Windows.Forms.MessageBox]::Show('Enter a target hash/value and select a wordlist first.', 'Missing Information', 'OK', 'Warning') | Out-Null
        return
    }
    Ensure-AesMaterial ([int]$comboKey.SelectedItem)
    $txtAESKey.Text = [Convert]::ToBase64String($Script:AESKey)
    $txtAESIV.Text = [Convert]::ToBase64String($Script:AESIV)
    $Script:HashQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    $Script:HashShared = [hashtable]::Synchronized(@{ Cancel=$false; Pause=$false; Running=$false; Status='Queued'; Current=''; CurrentValue=''; FoundPassword=''; BestWord=''; BestValue=''; BestDistance=[int]::MaxValue; Index=0; Total=0 })
    $txtHashLog.Clear(); $txtHashCurrent.Clear(); $txtHashFound.Clear(); $txtHashBestDist.Clear()
    $btnHashStart.Enabled = $false; $btnHashPause.Enabled = $true; $btnHashCancel.Enabled = $true
    $hashProgress.Value = 0
    $Script:HashStartTime = Get-Date
    $Script:HashPS = [PowerShell]::Create()
    [void]$Script:HashPS.AddScript($hashScript).AddArgument([string]$comboAlgo.SelectedItem).AddArgument($txtTargetHash.Text.Trim()).AddArgument($txtHashWordlist.Text.Trim()).AddArgument($txtSalt.Text).AddArgument([string]$comboSaltMode.SelectedItem).AddArgument([int]$comboKey.SelectedItem).AddArgument([string]$comboMode.SelectedItem).AddArgument($txtAESKey.Text.Trim()).AddArgument($txtAESIV.Text.Trim()).AddArgument($Script:HashShared).AddArgument($Script:HashQueue)
    $Script:HashAsync = $Script:HashPS.BeginInvoke()
    $hashTimer.Start()
})

$btnHashPause.Add_Click({
    if (-not $Script:HashShared) { return }
    $Script:HashShared.Pause = -not $Script:HashShared.Pause
    $btnHashPause.Text = if ($Script:HashShared.Pause) { 'Resume' } else { 'Pause' }
})

$btnHashCancel.Add_Click({
    if ($Script:HashShared) { $Script:HashShared.Cancel = $true }
    Write-HashLog 'Cancel requested.'
})

$form.Add_FormClosing({ Stop-StegoWorker; Stop-HashWorker })
#endregion

#region Final Init
New-AesMaterial 128
$txtAESKey.Text = [Convert]::ToBase64String($Script:AESKey)
$txtAESIV.Text = [Convert]::ToBase64String($Script:AESIV)
Set-ControlTreeTheme $form $false
Write-StegoLog 'Ready. Select openstego.jar, a stego image, a wordlist, and an output folder.'
Write-HashLog 'Ready. Paste a target hash/value, select an algorithm, choose a wordlist, then start the solver.'
[void]$form.ShowDialog()
#endregion
