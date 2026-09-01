; Graphical Windows installer for Nebula Mesh.
;
; The wizard collects the enrollment details and the service choices, then
; hands them to Install-NebulaMesh.ps1, which does the actual work (download,
; checksum verification, ACL hardening, enrollment, service registration).
; Keeping the logic in the PowerShell script means the GUI and the unattended
; CLI install follow exactly the same code path.
;
; Build with deploy\windows\build-installer.ps1 (or ISCC.exe directly).

#define AppName "Nebula Mesh"
#define AppPublisher "forgekeep"
#define AppURL "https://github.com/forgekeep/nebula-mesh"
#define RepoRoot "..\.."

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
; Release tags the installed host will pull. "latest" resolves at install time.
#ifndef AgentVersion
  #define AgentVersion "latest"
#endif
#ifndef NebulaVersion
  #define NebulaVersion "latest"
#endif
; Windows' file-version resource must be purely numeric, while AppVersion may
; carry a pre-release suffix (0.14.0-rc1). build-installer.ps1 passes the
; numeric core; the fallback keeps a direct ISCC invocation compiling.
#ifndef VersionInfo
  #define VersionInfo "0.0.0"
#endif

[Setup]
AppId={{9C0100D2-ABBD-4056-8355-BAC15C91B5ED}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
VersionInfoVersion={#VersionInfo}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\Nebula Mesh
DefaultGroupName=Nebula Mesh
DisableProgramGroupPage=yes
LicenseFile={#RepoRoot}\LICENSE
OutputDir={#RepoRoot}\dist\windows-installer
OutputBaseFilename=nebula-mesh-setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Both services run as LocalSystem and the installer writes below
; %ProgramFiles% and %ProgramData%, so it is admin-only by construction.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName}
MinVersion=10.0
CloseApplications=no
; Take the language from the host's locale; only ask when it matches neither.
ShowLanguageDialog=auto

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
en.TypeFull=Nebula and the management agent
es.TypeFull=Nebula y el agente de gestión
en.TypeAgentOnly=Management agent only (Nebula already installed)
es.TypeAgentOnly=Solo el agente de gestión (Nebula ya instalado)
en.TypeCustom=Custom
es.TypeCustom=Personalizada

en.CompAgent=nebula-agent (enrollment and config updates)
es.CompAgent=nebula-agent (inscripción y actualización de configuración)
en.CompNebula=Nebula (downloaded from slackhq/nebula)
es.CompNebula=Nebula (se descarga de slackhq/nebula)

en.TaskSvcNebula=Register and start the "nebula" service
es.TaskSvcNebula=Registrar e iniciar el servicio "nebula"
en.TaskSvcAgent=Register and start the "NebulaMeshAgent" service
es.TaskSvcAgent=Registrar e iniciar el servicio "NebulaMeshAgent"
en.TaskFirewall=Allow inbound UDP to nebula.exe (lighthouses, relays)
es.TaskFirewall=Permitir UDP entrante a nebula.exe (lighthouses, relays)
en.TaskPath=Add the install folder to PATH (for nebula-cert)
es.TaskPath=Añadir la carpeta de instalación al PATH (para nebula-cert)

en.EnrollCaption=Management server
es.EnrollCaption=Servidor de gestión
en.EnrollDescription=Enroll this host into your Nebula network
es.EnrollDescription=Inscribe este equipo en tu red Nebula
en.EnrollSubCaption=These are handed to "nebula-agent enroll". The token is single-use and is%nwritten to a temporary owner-only file, never to a command line.
es.EnrollSubCaption=Se pasan a "nebula-agent enroll". El token es de un solo uso y se escribe%nen un fichero temporal de acceso restringido, nunca en una línea de comandos.
en.EnrollUrlPrompt=Server URL (e.g. https://mgmt.example.com:8080):
es.EnrollUrlPrompt=URL del servidor (p. ej. https://mgmt.example.com:8080):
en.EnrollTokenPrompt=Enrollment token:
es.EnrollTokenPrompt=Token de inscripción:
en.EnrollSkip=Skip enrollment (the agent waits in standby until you enroll)
es.EnrollSkip=Omitir la inscripción (el agente espera en reposo hasta que la hagas)
en.EnrollAlready=This host is already enrolled (%1).%nIts identity is kept. Clear the checkbox only to enroll it again from scratch.
es.EnrollAlready=Este equipo ya está inscrito (%1).%nSe conserva su identidad. Desmarca la casilla solo para volver a inscribirlo desde cero.

en.ErrUrlRequired=Enter the management server URL, for example:%nhttps://mgmt.example.com:8080
es.ErrUrlRequired=Introduce la URL del servidor de gestión, por ejemplo:%nhttps://mgmt.example.com:8080
en.ErrTokenRequired=Enter the single-use enrollment token issued by the management server,%nor tick "Skip enrollment" to enroll this host later.
es.ErrTokenRequired=Introduce el token de un solo uso emitido por el servidor de gestión,%no marca "Omitir la inscripción" para inscribir este equipo más tarde.
en.WarnPlaintextHttp=That URL is plaintext http.%n%nThe enrollment token and this host's Nebula config would travel in cleartext, where anyone on the path can read or replace them.%n%nContinue anyway?
es.WarnPlaintextHttp=Esa URL es http sin cifrar.%n%nEl token de inscripción y la configuración Nebula de este equipo viajarían en claro, donde cualquiera en la ruta puede leerlos o sustituirlos.%n%n¿Continuar de todos modos?

en.ReadyEnrollment=Enrollment:
es.ReadyEnrollment=Inscripción:
en.ReadySkipped=skipped - the agent waits in standby
es.ReadySkipped=omitida: el agente espera en reposo
en.ReadyReplaces=replaces this host's existing identity
es.ReadyReplaces=sustituye la identidad actual de este equipo
en.ReadyDataDirs=Data directories:
es.ReadyDataDirs=Directorios de datos:

en.StatusDownloading=Downloading and verifying packages...
es.StatusDownloading=Descargando y verificando los paquetes...
en.ErrNoPowerShell=Cannot start Windows PowerShell.
es.ErrNoPowerShell=No se puede iniciar Windows PowerShell.
en.ErrTokenFile=Cannot write the temporary token file.
es.ErrTokenFile=No se puede escribir el fichero temporal del token.
en.ErrInstallFailed=The installation step failed (exit %1).
es.ErrInstallFailed=El paso de instalación ha fallado (código %1).
en.ErrFullLog=Full log: %1
es.ErrFullLog=Registro completo: %1

en.FinishedFailed=The files were installed, but the host was not enrolled.
es.FinishedFailed=Los ficheros se han instalado, pero el equipo no se ha inscrito.
en.FailHeader=The installation could not be completed.
es.FailHeader=No se ha podido completar la instalación.
en.FailServerUnreachable=The management server could not be reached at that address.
es.FailServerUnreachable=No se ha podido contactar con el servidor de gestión en esa dirección.
en.FailServerTls=The management server's TLS certificate is not trusted by this machine.
es.FailServerTls=Este equipo no confía en el certificado TLS del servidor de gestión.
en.FailServerNotMgmt=That address answered, but it is not a Nebula Mesh management server.
es.FailServerNotMgmt=Esa dirección responde, pero no es un servidor de gestión de Nebula Mesh.
en.FailServerRejectedProfile=The management server refused this host's file paths, and needs updating.
es.FailServerRejectedProfile=El servidor de gestión ha rechazado las rutas de este equipo; hay que actualizarlo.
en.FailTokenInvalid=The management server did not accept that enrollment token.
es.FailTokenInvalid=El servidor de gestión no ha aceptado ese token de inscripción.
en.FailTokenUsed=That enrollment token has already been used.
es.FailTokenUsed=Ese token de inscripción ya se ha usado.
en.FailTokenExpired=That enrollment token has expired.
es.FailTokenExpired=Ese token de inscripción ha caducado.
en.FailAlreadyEnrolled=This host already has a Nebula identity.
es.FailAlreadyEnrolled=Este equipo ya tiene una identidad Nebula.
en.FailDetails=Details:
es.FailDetails=Detalles:
en.FailNothingChanged=Nothing was enrolled and the enrollment token was not spent. Correct the problem above and run this installer again.
es.FailNothingChanged=No se ha inscrito nada y el token de inscripción no se ha gastado. Corrige el problema y vuelve a ejecutar el instalador.

en.FinishedText=Nebula Mesh is installed.%n%nCheck the services:%n    Get-Service NebulaMeshAgent, nebula%n%nAgent logs go to the Windows Application event log under the NebulaMeshAgent source.%nInstall log: %1
es.FinishedText=Nebula Mesh está instalado.%n%nRevisa los servicios:%n    Get-Service NebulaMeshAgent, nebula%n%nEl agente registra en el visor de eventos de Windows (Aplicación, origen NebulaMeshAgent).%nRegistro de instalación: %1

en.UninstallPurge=Also delete this host's Nebula identity?%n%n%1%n%2%n%nThis removes the private key and certificates. The host would have to be enrolled again from scratch. Choose No to keep them.
es.UninstallPurge=¿Eliminar también la identidad Nebula de este equipo?%n%n%1%n%2%n%nSe borran la clave privada y los certificados. Habría que volver a inscribir el equipo desde cero. Elige No para conservarlos.
en.UninstallFailed=The service removal step reported exit %1.%nCheck the services with: Get-Service NebulaMeshAgent, nebula
es.UninstallFailed=El paso de eliminación de servicios ha devuelto el código %1.%nRevisa los servicios con: Get-Service NebulaMeshAgent, nebula

[Types]
Name: "full"; Description: "{cm:TypeFull}"
Name: "agentonly"; Description: "{cm:TypeAgentOnly}"
Name: "custom"; Description: "{cm:TypeCustom}"; Flags: iscustom

[Components]
Name: "agent"; Description: "{cm:CompAgent}"; Types: full agentonly custom; Flags: fixed
Name: "nebula"; Description: "{cm:CompNebula}"; Types: full custom

[Tasks]
Name: "svcnebula"; Description: "{cm:TaskSvcNebula}"; Components: nebula
Name: "svcagent"; Description: "{cm:TaskSvcAgent}"
Name: "firewall"; Description: "{cm:TaskFirewall}"; Components: nebula; Flags: unchecked
Name: "addpath"; Description: "{cm:TaskPath}"; Flags: unchecked

[Files]
Source: "Install-NebulaMesh.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; DestName: "README-windows.md"; Flags: ignoreversion
Source: "{#RepoRoot}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Nebula Mesh documentation"; Filename: "{#AppURL}"
Name: "{group}\Uninstall Nebula Mesh"; Filename: "{uninstallexe}"

; The PowerShell script installs the binaries, so Setup's own uninstall log
; does not know about them. Remove them explicitly.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\dist"
Type: files; Name: "{app}\nebula.exe"
Type: files; Name: "{app}\nebula-cert.exe"
Type: files; Name: "{app}\nebula-agent.exe"
Type: files; Name: "{app}\wintun.dll"
Type: files; Name: "{app}\agent.example.yml"
Type: dirifempty; Name: "{app}"

[Code]
var
  EnrollPage: TInputQueryWizardPage;
  SkipEnrollCheck: TNewCheckBox;
  EnrolledHint: TNewStaticText;
  AllowInsecureHttp: Boolean;
  InstallLog: TStringList;
  TokenFileParam: String;
  { The script classifies its own failures and marks the explanation with "!!";
    these hold the code and the detail lines lifted back out of its output. }
  FailureCode: String;
  FailureText: TStringList;
  LogSaved: Boolean;
  InstallFailed: Boolean;
  FailureSummary: String;

// CustomMessage() returns the raw message; the line-break placeholder is only
// expanded by the cm: constant. Do it here so [Code] and the sections render
// the same text. StringChangeEx takes a var parameter, which Result cannot be.
function Msg(const Key: String): String;
var
  Text: String;
begin
  Text := CustomMessage(Key);
  StringChangeEx(Text, '%n', #13#10, True);
  Result := Text;
end;

function AgentConfigPath: String;
begin
  Result := ExpandConstant('{commonappdata}\Nebula Mesh\Agent\agent.yml');
end;

function LogFilePath: String;
begin
  Result := ExpandConstant('{commonappdata}\Nebula Mesh\install.log');
end;

function AlreadyEnrolled: Boolean;
begin
  Result := FileExists(AgentConfigPath);
end;

{ One translated sentence naming the problem. The detail lines the script
  produced carry the specifics (the address tried, the command to check it),
  so they are shown alongside this rather than replaced by it.
  Declared here because CurPageChanged uses it. }
function LocalizedFailureHeadline: String;
begin
  if FailureCode = 'server-unreachable' then
    Result := Msg('FailServerUnreachable')
  else if FailureCode = 'server-tls' then
    Result := Msg('FailServerTls')
  else if FailureCode = 'server-not-mgmt' then
    Result := Msg('FailServerNotMgmt')
  else if FailureCode = 'server-rejected-profile' then
    Result := Msg('FailServerRejectedProfile')
  else if FailureCode = 'token-invalid' then
    Result := Msg('FailTokenInvalid')
  else if FailureCode = 'token-used' then
    Result := Msg('FailTokenUsed')
  else if FailureCode = 'token-expired' then
    Result := Msg('FailTokenExpired')
  else if FailureCode = 'already-enrolled' then
    Result := Msg('FailAlreadyEnrolled')
  else
    Result := Msg('FailHeader');
end;

{ True for the failures that happen before anything is written or the token is
  spent, so that reassurance is only offered when it is actually true. }
function FailedBeforeAnyChange: Boolean;
begin
  Result := (FailureCode = 'server-unreachable') or (FailureCode = 'server-tls') or
    (FailureCode = 'server-not-mgmt') or (FailureCode = 'server-rejected-profile');
end;

function PowerShellPath: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

{ Mirrors the guard in Install-NebulaMesh.ps1 / ValidateAgentServerURL: an
  absolute http(s) URL with a host. }
function LooksLikeServerUrl(const Url: String): Boolean;
var
  Rest: String;
begin
  Result := False;
  if Lowercase(Copy(Url, 1, 8)) = 'https://' then
    Rest := Copy(Url, 9, Length(Url))
  else if Lowercase(Copy(Url, 1, 7)) = 'http://' then
    Rest := Copy(Url, 8, Length(Url))
  else
    Exit;
  Result := (Trim(Rest) <> '') and (Pos(' ', Trim(Rest)) = 0);
end;

function IsPlaintextHttp(const Url: String): Boolean;
begin
  Result := Lowercase(Copy(Url, 1, 7)) = 'http://';
end;

procedure SkipEnrollClicked(Sender: TObject);
var
  Enabled: Boolean;
begin
  Enabled := not SkipEnrollCheck.Checked;
  EnrollPage.Edits[0].Enabled := Enabled;
  EnrollPage.Edits[1].Enabled := Enabled;
  EnrollPage.PromptLabels[0].Enabled := Enabled;
  EnrollPage.PromptLabels[1].Enabled := Enabled;
end;

{ /SERVERURL= and /TOKENFILE= drive an unattended install. There is deliberately
  no /TOKEN=: a token on the command line is visible to every process on the
  box, which is exactly what the file-based hand-off avoids. }
procedure ReadSetupParameters;
begin
  TokenFileParam := Trim(ExpandConstant('{param:TokenFile|}'));
  EnrollPage.Values[0] := Trim(ExpandConstant('{param:ServerUrl|}'));
  if ExpandConstant('{param:AllowInsecureHttp|0}') = '1' then
    AllowInsecureHttp := True;
  { Nothing to enroll with: install the files and let the agent stand by
    rather than failing the whole run. }
  if WizardSilent and (EnrollPage.Values[0] = '') then
    SkipEnrollCheck.Checked := True;
end;

function EnrollmentRequested: Boolean;
begin
  Result := (not SkipEnrollCheck.Checked) and (Trim(EnrollPage.Values[0]) <> '');
end;

procedure InitializeWizard;
begin
  AllowInsecureHttp := False;

  EnrollPage := CreateInputQueryPage(wpSelectTasks,
    Msg('EnrollCaption'),
    Msg('EnrollDescription'),
    Msg('EnrollSubCaption'));
  EnrollPage.Add(Msg('EnrollUrlPrompt'), False);
  EnrollPage.Add(Msg('EnrollTokenPrompt'), True);

  SkipEnrollCheck := TNewCheckBox.Create(WizardForm);
  SkipEnrollCheck.Parent := EnrollPage.Surface;
  SkipEnrollCheck.Left := EnrollPage.Edits[1].Left;
  SkipEnrollCheck.Top := EnrollPage.Edits[1].Top + EnrollPage.Edits[1].Height + ScaleY(16);
  SkipEnrollCheck.Width := EnrollPage.SurfaceWidth;
  SkipEnrollCheck.Height := ScaleY(17);
  SkipEnrollCheck.Caption := Msg('EnrollSkip');
  SkipEnrollCheck.OnClick := @SkipEnrollClicked;

  EnrolledHint := TNewStaticText.Create(WizardForm);
  EnrolledHint.Parent := EnrollPage.Surface;
  EnrolledHint.Left := SkipEnrollCheck.Left;
  EnrolledHint.Top := SkipEnrollCheck.Top + SkipEnrollCheck.Height + ScaleY(12);
  EnrolledHint.Width := EnrollPage.SurfaceWidth;
  EnrolledHint.WordWrap := True;
  EnrolledHint.Caption := '';
  EnrolledHint.Visible := False;

  ReadSetupParameters;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    { Headline only here - the full detail was shown in its own dialog, and a
      long caption is silently clipped by this label rather than wrapped. }
    if InstallFailed then
      WizardForm.FinishedLabel.Caption := Msg('FinishedFailed') + #13#10#13#10 +
        LocalizedFailureHeadline + #13#10#13#10 +
        FmtMessage(Msg('ErrFullLog'), [LogFilePath])
    else
      WizardForm.FinishedLabel.Caption := FmtMessage(Msg('FinishedText'), [LogFilePath]);
  end;

  if CurPageID = EnrollPage.ID then
  begin
    { An upgrade must not silently re-enroll: an existing agent.yml means this
      host already has an identity, so default to leaving it alone. }
    if AlreadyEnrolled and (EnrollPage.Values[0] = '') then
    begin
      SkipEnrollCheck.Checked := True;
      EnrolledHint.Caption := FmtMessage(Msg('EnrollAlready'), [AgentConfigPath]);
      EnrolledHint.Visible := True;
      SkipEnrollClicked(nil);
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Url, Token: String;
begin
  Result := True;
  if CurPageID <> EnrollPage.ID then
    Exit;
  if SkipEnrollCheck.Checked then
    Exit;

  Url := Trim(EnrollPage.Values[0]);
  Token := Trim(EnrollPage.Values[1]);

  if not LooksLikeServerUrl(Url) then
  begin
    MsgBox(Msg('ErrUrlRequired'), mbError, MB_OK);
    Result := False;
    Exit;
  end;

  if IsPlaintextHttp(Url) then
  begin
    if MsgBox(Msg('WarnPlaintextHttp'), mbConfirmation,
      MB_YESNO or MB_DEFBUTTON2) <> IDYES then
    begin
      Result := False;
      Exit;
    end;
    AllowInsecureHttp := True;
  end;

  if (Token = '') and (TokenFileParam = '') then
  begin
    MsgBox(Msg('ErrTokenRequired'), mbError, MB_OK);
    Result := False;
  end;
end;

function ServicesArgument: String;
var
  WantAgent, WantNebula: Boolean;
begin
  WantAgent := WizardIsTaskSelected('svcagent');
  WantNebula := WizardIsTaskSelected('svcnebula') and WizardIsComponentSelected('nebula');
  if WantAgent and WantNebula then
    Result := 'Both'
  else if WantAgent then
    Result := 'Agent'
  else if WantNebula then
    Result := 'Nebula'
  else
    Result := 'None';
end;

function UpdateReadyMemo(const Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine +
    MemoComponentsInfo + NewLine + NewLine;
  if MemoTasksInfo <> '' then
    Result := Result + MemoTasksInfo + NewLine + NewLine;

  Result := Result + Msg('ReadyEnrollment') + NewLine;
  if not EnrollmentRequested then
    Result := Result + Space + Msg('ReadySkipped') + NewLine
  else
  begin
    Result := Result + Space + Trim(EnrollPage.Values[0]) + NewLine;
    if AlreadyEnrolled then
      Result := Result + Space + Msg('ReadyReplaces') + NewLine;
  end;

  Result := Result + NewLine + Msg('ReadyDataDirs') + NewLine +
    Space + ExpandConstant('{commonappdata}\Nebula') + NewLine +
    Space + ExpandConstant('{commonappdata}\Nebula Mesh\Agent') + NewLine;
end;

{ Streams the PowerShell output into the wizard's status line and the log. }
procedure OnScriptOutput(const S: String; const Error, FirstLine: Boolean);
var
  Line: String;
begin
  InstallLog.Add(S);
  Line := Trim(S);

  { "!!" marks the script's own diagnosis of a failure. Collect it rather than
    showing it as progress - it becomes the error dialog. }
  if Copy(Line, 1, 2) = '!!' then
  begin
    Line := Trim(Copy(Line, 3, Length(Line)));
    if Copy(Line, 1, 6) = 'code: ' then
      FailureCode := Trim(Copy(Line, 7, Length(Line)))
    else if (Line <> '') and (Line <> 'INSTALL FAILED') then
      FailureText.Add(Line);
    Exit;
  end;

  if Line <> '' then
  begin
    if Length(Line) > 90 then
      Line := Copy(Line, 1, 87) + '...';
    WizardForm.StatusLabel.Caption := Line;
  end;
end;


function StagedArchive(const Pattern: String): String;
var
  Rec: TFindRec;
  Dir: String;
begin
  Result := '';
  Dir := ExpandConstant('{srcexe}');
  Dir := ExtractFileDir(Dir);
  if FindFirst(AddBackslash(Dir) + Pattern, Rec) then
  try
    Result := AddBackslash(Dir) + Rec.Name;
  finally
    FindClose(Rec);
  end;
end;

function Quoted(const S: String): String;
begin
  Result := '"' + S + '"';
end;

function BuildScriptArguments(const TokenFile: String): String;
var
  Args, Staged: String;
begin
  Args := '-NoProfile -ExecutionPolicy Bypass -File ' +
    Quoted(ExpandConstant('{app}\Install-NebulaMesh.ps1')) +
    ' -Unattended' +
    ' -InstallDir ' + Quoted(ExpandConstant('{app}')) +
    ' -Services ' + ServicesArgument;

  if WizardIsComponentSelected('nebula') then
  begin
    Args := Args + ' -NebulaVersion ' + Quoted('{#NebulaVersion}');
    Staged := StagedArchive('nebula-windows-*.zip');
    if Staged <> '' then
      Args := Args + ' -NebulaZip ' + Quoted(Staged);
  end
  else
    Args := Args + ' -SkipNebula';

  Args := Args + ' -AgentVersion ' + Quoted('{#AgentVersion}');
  Staged := StagedArchive('nebula-agent_*_windows_*.zip');
  if Staged <> '' then
    Args := Args + ' -AgentZip ' + Quoted(Staged);

  if not EnrollmentRequested then
    Args := Args + ' -SkipEnroll'
  else
  begin
    Args := Args + ' -ServerUrl ' + Quoted(Trim(EnrollPage.Values[0])) +
      ' -TokenFile ' + Quoted(TokenFile);
    if AllowInsecureHttp then
      Args := Args + ' -AllowInsecureHttp';
    { An operator who reaches this page on an already-enrolled host and clears
      the checkbox means it: replace the identity. }
    if AlreadyEnrolled then
      Args := Args + ' -Force';
  end;

  if WizardIsTaskSelected('firewall') and WizardIsComponentSelected('nebula') then
    Args := Args + ' -AddFirewallRule';
  if WizardIsTaskSelected('addpath') then
    Args := Args + ' -AddToPath';

  Result := Args;
end;

{ Writes the token where only SYSTEM and Administrators can read it, so the
  secret never sits in a command line or in a world-readable temp file. }
function WriteTokenFile: String;
var
  Path: String;
  ResultCode: Integer;
begin
  Path := ExpandConstant('{tmp}\enroll.token');
  if not SaveStringToFile(Path, Trim(EnrollPage.Values[1]), False) then
    RaiseException(Msg('ErrTokenFile'));
  Exec(ExpandConstant('{sys}\icacls.exe'),
    Quoted(Path) + ' /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F /C',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := Path;
end;

{ Best effort by design: if the log cannot be written, the operator must still
  get the diagnosis. Letting this raise would replace "the host name cannot be
  resolved" with "cannot create file", which is the opposite of useful. }
procedure SaveInstallLog;
var
  Dir: String;
begin
  LogSaved := False;
  try
    Dir := ExpandConstant('{commonappdata}\Nebula Mesh');
    if not DirExists(Dir) then
      CreateDir(Dir);
    InstallLog.SaveToFile(LogFilePath);
    LogSaved := True;
  except
    { swallowed on purpose - see above }
  end;
end;

function LogTail(Lines: Integer): String;
var
  I, First: Integer;
begin
  Result := '';
  First := InstallLog.Count - Lines;
  if First < 0 then
    First := 0;
  for I := First to InstallLog.Count - 1 do
    Result := Result + Trim(InstallLog[I]) + #13#10;
end;

{ Builds what the operator actually reads: a translated headline, the concrete
  details, what state the machine is in, and where the full log lives. Falls
  back to the tail of the log only when the script died without diagnosing
  itself. }
function BuildFailureMessage(ResultCode: Integer): String;
var
  I: Integer;
begin
  if FailureText.Count = 0 then
  begin
    Result := FmtMessage(Msg('ErrInstallFailed'), [IntToStr(ResultCode)]) + #13#10#13#10 +
      LogTail(8);
  end
  else
  begin
    Result := LocalizedFailureHeadline + #13#10#13#10 + Msg('FailDetails') + #13#10;
    for I := 0 to FailureText.Count - 1 do
      Result := Result + '    ' + FailureText[I] + #13#10;

    if FailedBeforeAnyChange then
      Result := Result + #13#10 + Msg('FailNothingChanged') + #13#10;
  end;

  { Only point at the log when it actually got written. }
  if LogSaved then
    Result := Result + #13#10 + FmtMessage(Msg('ErrFullLog'), [LogFilePath]);
end;

procedure RunInstallerScript;
var
  TokenFile: String;
  Arguments: String;
  ResultCode: Integer;
  Temporary: Boolean;
begin
  TokenFile := '';
  Temporary := False;
  FailureCode := '';
  InstallLog := TStringList.Create;
  FailureText := TStringList.Create;
  try
    if EnrollmentRequested then
    begin
      { An operator-supplied token file is used as it stands and left alone;
        only the one typed into the wizard is written here, and then shredded. }
      if TokenFileParam <> '' then
        TokenFile := TokenFileParam
      else
      begin
        TokenFile := WriteTokenFile;
        Temporary := True;
      end;
    end;

    Arguments := BuildScriptArguments(TokenFile);
    WizardForm.StatusLabel.Caption := Msg('StatusDownloading');

    if not ExecAndLogOutput(PowerShellPath, Arguments, ExpandConstant('{app}'),
      SW_HIDE, ewWaitUntilTerminated, ResultCode, @OnScriptOutput) then
    begin
      SaveInstallLog;
      RaiseException(Msg('ErrNoPowerShell'));
    end;

    SaveInstallLog;

    { Not RaiseException: that prefixes the text with "Runtime error (at x:y)",
      which buries the explanation under something the operator cannot act on.
      Show the diagnosis on its own, then carry the failure to the final page.
      The files are installed either way - only the enrollment step failed, and
      it can be retried without reinstalling. }
    if ResultCode <> 0 then
    begin
      InstallFailed := True;
      FailureSummary := BuildFailureMessage(ResultCode);
      MsgBox(FailureSummary, mbCriticalError, MB_OK);
    end;
  finally
    if Temporary and (TokenFile <> '') then
      DeleteFile(TokenFile);
    InstallLog.Free;
    FailureText.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RunInstallerScript;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Arguments: String;
  ResultCode: Integer;
  Purge: Boolean;
begin
  if CurUninstallStep <> usUninstall then
    Exit;
  if not FileExists(ExpandConstant('{app}\Install-NebulaMesh.ps1')) then
    Exit;

  { A silent uninstall has nobody to answer the question, and MsgBox would
    block it forever. Keep the identity: that is the recoverable choice, and
    /PURGEDATA is there for the operator who means the other one. }
  if UninstallSilent then
    Purge := ExpandConstant('{param:PurgeData|0}') = '1'
  else
    Purge := MsgBox(FmtMessage(Msg('UninstallPurge'), [
        ExpandConstant('{commonappdata}\Nebula'),
        ExpandConstant('{commonappdata}\Nebula Mesh')]),
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;

  Arguments := '-NoProfile -ExecutionPolicy Bypass -File ' +
    Quoted(ExpandConstant('{app}\Install-NebulaMesh.ps1')) +
    ' -Uninstall -Unattended -KeepInstallDir' +
    ' -InstallDir ' + Quoted(ExpandConstant('{app}'));
  if Purge then
    Arguments := Arguments + ' -PurgeData';

  Exec(PowerShellPath, Arguments, ExpandConstant('{app}'), SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 0 then
    MsgBox(FmtMessage(Msg('UninstallFailed'), [IntToStr(ResultCode)]), mbError, MB_OK);
end;
