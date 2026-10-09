package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// nrptScript is immutable code; all operation values arrive in one JSON environment object.
// The second ownership check closes the read-to-remove window against ordinary concurrent edits.
const nrptScript = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    Import-Module -Name ([IO.Path]::Combine($env:FORTIX_SYSTEM_DIRECTORY, 'WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
    Import-Module -Name ([IO.Path]::Combine($env:FORTIX_SYSTEM_DIRECTORY, 'WindowsPowerShell\v1.0\Modules\DnsClient\DnsClient.psd1')) -ErrorAction Stop
    $request = ConvertFrom-Json -InputObject $env:FORTIX_NRPT_REQUEST
    # Addresses may be returned as either arrays or semicolon-separated provider strings.
    function Get-Servers($rule) {
        foreach ($server in @($rule.NameServers)) {
            foreach ($part in ([string]$server).Split(';')) {
                if ($part.Trim().Length -gt 0) { ([Net.IPAddress]::Parse($part.Trim())).ToString() }
            }
        }
    }
    # Only these values establish ownership; presentation fields are deliberately excluded.
    function Convert-Rule($rule) {
        @{name=[string]$rule.Name; namespaces=@($rule.Namespace); servers=@(Get-Servers $rule); comment=[string]$rule.Comment}
    }
    # Label boundaries prevent example.com from conflicting with notexample.com.
    function Test-Overlap($left, $right) {
        if ($left -eq '.' -or $right -eq '.') { return $true }
        $left = $left.TrimStart('*').Trim('.').ToLowerInvariant()
        $right = $right.TrimStart('*').Trim('.').ToLowerInvariant()
        return $left -eq $right -or $left.EndsWith('.' + $right) -or $right.EndsWith('.' + $left)
    }
    # Re-read full ownership immediately before removal, never relying only on a GUID.
    function Test-Values($rule, $expected) {
        if ([string]$rule.Comment -cne [string]$expected.comment) { return $false }
        $names = @($rule.Namespace | ForEach-Object { $_.TrimEnd('.').ToLowerInvariant() } | Sort-Object)
        $expectedNames = @($expected.namespaces | ForEach-Object { $_.TrimEnd('.').ToLowerInvariant() } | Sort-Object)
        $servers = @(Get-Servers $rule | Sort-Object -Unique)
        $expectedServers = @($expected.servers | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() } | Sort-Object -Unique)
        return ($names -join '|') -ceq ($expectedNames -join '|') -and ($servers -join '|') -ceq ($expectedServers -join '|')
    }
    switch ($request.operation) {
        'snapshot' {
            $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | ForEach-Object { Convert-Rule $_ })
            $policies = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | ForEach-Object { Convert-Rule $_ })
            $result = @{ok=$true; rules=$rules; policies=$policies}
        }
        'add' {
            $conflict = $false
            $existing = @(Get-DnsClientNrptRule -ErrorAction Stop) + @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
            foreach ($rule in $existing) {
                foreach ($namespace in @($rule.Namespace)) {
                    foreach ($desired in @($request.rule.namespaces)) {
                        if (Test-Overlap $namespace $desired) { $conflict = $true }
                    }
                }
            }
            if ($conflict) {
                $result = @{ok=$false; conflict=$true; error='DNS namespace overlaps an existing DNS rule or effective DNS policy'}
            } else {
                $added = Add-DnsClientNrptRule -Namespace ([string[]]$request.rule.namespaces) -NameServers ([string[]]$request.rule.servers) -Comment ([string]$request.rule.comment) -DisplayName 'Fortix split DNS' -PassThru -ErrorAction Stop
                $result = @{ok=$true; name=[string]$added.Name}
            }
        }
        'remove' {
            $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Name -ceq $request.rule.name })
            if ($rules.Count -ne 1 -or -not (Test-Values $rules[0] $request.rule)) {
                throw 'DNS rule identity changed; journal retained'
            }
            Remove-DnsClientNrptRule -Name ([string]$request.rule.name) -Force -ErrorAction Stop
            $result = @{ok=$true}
        }
        default { throw 'Invalid DNS operation' }
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 8 -Compress))
} catch {
    [Console]::Out.WriteLine((@{ok=$false; error=[string]$_.Exception.Message} | ConvertTo-Json -Depth 4 -Compress))
}

`

// powershellNRPTRunner executes only the system PowerShell image inside a kill-on-close job.
type powershellNRPTRunner struct{}

// encodeNRPTRequest bounds the single data object independently of script and command line.
func encodeNRPTRequest(request nrptRequest) ([]byte, error) {
	if request.Operation != "snapshot" && request.Operation != "add" && request.Operation != "remove" {
		return nil, errors.New("invalid DNS operation")
	}
	data, err := json.Marshal(request)
	if err == nil && len(data) > nrptRequestLimit {
		err = errors.New("DNS request exceeds limit")
	}
	return data, err
}

// nrptEnvironment excludes inherited module paths and supplies the OS-resolved system directory.
func nrptEnvironment(system string, data []byte) []uint16 {
	root := filepath.Dir(system)
	entries := []string{
		"FORTIX_NRPT_REQUEST=" + string(data),
		"FORTIX_SYSTEM_DIRECTORY=" + system,
		"PSModulePath=" + filepath.Join(system, `WindowsPowerShell\v1.0\Modules`),
		"SystemDrive=" + filepath.VolumeName(system),
		"SystemRoot=" + root,
		"TEMP=" + filepath.Join(root, "Temp"),
		"TMP=" + filepath.Join(root, "Temp"),
		"WINDIR=" + root,
	}
	return utf16.Encode([]rune(strings.Join(entries, "\x00") + "\x00\x00"))
}

// nrptPipe clears the inheritance flags on both parent endpoints before they are published.
func nrptPipe() (*os.File, *os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	for _, file := range []*os.File{reader, writer} {
		if err := windows.SetHandleInformation(windows.Handle(file.Fd()), windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			reader.Close()
			writer.Close()
			return nil, nil, err
		}
	}
	return reader, writer, nil
}

// inheritNRPTHandle duplicates just a pipe endpoint, leaving parent handles non-inheritable.
func inheritNRPTHandle(file *os.File) (windows.Handle, error) {
	var handle windows.Handle
	process := windows.CurrentProcess()
	err := windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &handle, 0, true, windows.DUPLICATE_SAME_ACCESS)
	return handle, err
}

// nrptOutput keeps bounded stdout and its read error together across the pipe reader.
type nrptOutput struct {
	data []byte
	err  error
}

// Run starts suspended, assigns the job before execution, and bounds the whole operation to 20s.
// A handle allowlist prevents inheriting service handles; no child can escape job cancellation.
func (powershellNRPTRunner) Run(parent context.Context, request nrptRequest) (nrptResponse, error) {
	var response nrptResponse
	data, err := encodeNRPTRequest(request)
	if err != nil {
		return response, err
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return response, err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return response, err
	}
	executable := filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`)
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return response, err
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"}))
	if err != nil {
		return response, err
	}
	directory, err := windows.UTF16PtrFromString(system)
	if err != nil {
		return response, err
	}
	input, inputWriter, err := nrptPipe()
	if err != nil {
		return response, err
	}
	defer input.Close()
	defer inputWriter.Close()
	outputReader, output, err := nrptPipe()
	if err != nil {
		return response, err
	}
	defer outputReader.Close()
	defer output.Close()
	stderr, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return response, err
	}
	defer stderr.Close()
	var handles []windows.Handle
	for _, file := range []*os.File{input, output, stderr} {
		handle, err := inheritNRPTHandle(file)
		if err != nil {
			for _, prior := range handles {
				windows.CloseHandle(prior)
			}
			return response, err
		}
		handles = append(handles, handle)
	}
	defer func() {
		for _, handle := range handles {
			windows.CloseHandle(handle)
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return response, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return response, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return response, err
	}
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return response, err
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = handles[0], handles[1], handles[2]
	environment := nrptEnvironment(system, data)
	if err := ctx.Err(); err != nil {
		return response, err
	}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(application, command, nil, nil, true, flags, &environment[0], directory, &startup.StartupInfo, &process); err != nil {
		return response, err
	}
	runtime.KeepAlive(handles)
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	// Terminate the still-suspended process if assignment fails; it never runs outside the job.
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		windows.TerminateProcess(process.Process, 1)
		return response, err
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return response, err
	}
	for _, handle := range handles {
		windows.CloseHandle(handle)
	}
	handles = nil
	input.Close()
	output.Close()
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(inputWriter, nrptScript)
		inputWriter.Close()
		written <- err
	}()
	read := make(chan nrptOutput, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(outputReader, nrptOutputLimit+1))
		read <- nrptOutput{data, err}
	}()
	var result nrptOutput
	var writeErr error
	var processDone, readDone, writeDone bool
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	processPoll := poll.C
	for !processDone || !readDone || !writeDone {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case result = <-read:
			readDone, read = true, nil
			if len(result.data) > nrptOutputLimit {
				err = errors.New("DNS response exceeds limit")
			} else if result.err != nil {
				err = result.err
			}
		case writeErr = <-written:
			writeDone, written = true, nil
			if writeErr != nil {
				err = writeErr
			}
		case <-processPoll:
			status, waitErr := windows.WaitForSingleObject(process.Process, 0)
			if waitErr != nil {
				err = waitErr
			} else if status == windows.WAIT_OBJECT_0 {
				processDone = true
				// Once signaled, block on pipe completion or cancellation instead of polling.
				processPoll = nil
				poll.Stop()
				// Descendants cannot keep the redirected pipes open after PowerShell exits.
				windows.TerminateJobObject(job, 1)
			}
		}
		if err != nil {
			killErr := windows.TerminateJobObject(job, 1)
			// Closing the job still kills its tree if explicit termination failed.
			closeErr := windows.CloseHandle(job)
			if closeErr == nil {
				job = 0
			}
			err = errors.Join(err, killErr, closeErr)
			inputWriter.Close()
			outputReader.Close()
			if !writeDone {
				<-written
			}
			if !readDone {
				<-read
			}
			return response, err
		}
	}
	var exit uint32
	if err := windows.GetExitCodeProcess(process.Process, &exit); err != nil {
		return response, err
	}
	return decodeNRPTResponse(result.data, exit)
}

// decodeNRPTResponse rejects oversized or malformed envelopes, including trailing JSON.
func decodeNRPTResponse(data []byte, exit uint32) (nrptResponse, error) {
	var response nrptResponse
	if len(data) > nrptOutputLimit {
		return response, errors.New("DNS response exceeds limit")
	}
	if err := decodeRecord(data, &response); err != nil {
		return response, errors.New("invalid DNS response JSON")
	}
	if exit != 0 && response.OK {
		return response, errors.New("Windows DNS process failed")
	}
	return response, nil
}
