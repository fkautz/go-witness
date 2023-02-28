// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package commandrun

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
	"golang.org/x/sys/unix"
)

const (
	MAX_PATH_LEN = 4096
)

type ptraceContext struct {
	parentPid            int
	mainProgram          string
	processes            map[int]*ProcessInfo
	exitCode             int
	hash                 []crypto.Hash
	environmentBlockList map[string]struct{}
}

func enableTracing(c *exec.Cmd) {
	c.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
}

func (r *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		parentPid:            c.Process.Pid,
		mainProgram:          c.Path,
		processes:            make(map[int]*ProcessInfo),
		hash:                 actx.Hashes(),
		environmentBlockList: r.environmentBlockList,
	}

	if err := pctx.runTrace(context.Background()); err != nil {
		return nil, err
	}

	r.ExitCode = pctx.exitCode

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}

	return pctx.procInfoArray(), nil
}

func (p *ptraceContext) runTrace(ctx context.Context) error {
	// Create a new channel for reporting errors.
	errChan := make(chan error)

	// Create a new goroutine to handle errors.
	go func() {
		for {
			select {
			case err := <-errChan:
				if err != nil {
					log.Errorf("error while tracing process: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Lock the current thread to ensure we don't accidentally switch to another thread while tracing.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Wait for the parent process to exit.
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(p.parentPid, &status, 0, nil)
	if err != nil {
		errChan <- fmt.Errorf("failed to wait for parent process: %w", err)
		return err
	}

	// Set ptrace options to trace system calls, process execution, and process forks.
	// Also set PTRACE_O_TRACESYSGOOD to ensure that any ptrace-generated SIGTRAP signals will have bit 7 set.
	// This allows us to distinguish between ptrace-generated signals and other signals.
	if err := unix.PtraceSetOptions(p.parentPid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		errChan <- fmt.Errorf("failed to set ptrace options: %w", err)
		return err
	}

	// Set up the process information for the parent process.
	procInfo := p.getProcInfo(p.parentPid)
	procInfo.Program = p.mainProgram

	// Start tracing by entering a syscall-stop state.
	if err := unix.PtraceSyscall(p.parentPid, 0); err != nil {
		errChan <- fmt.Errorf("failed to enter syscall-stop state: %w", err)
		return err
	}

	// Loop until the parent process exits.
	for {
		// Wait for any child process to change state.
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			errChan <- fmt.Errorf("failed to wait for child process: %w", err)
			return err
		}

		// If the parent process exited, return its exit code.
		if pid == p.parentPid && status.Exited() {
			p.exitCode = status.ExitStatus()
			return nil
		}

		// Determine the signal that caused the process to stop.
		sig := status.StopSignal()

		// Determine whether the signal was generated by ptrace.
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig

		// If the signal wasn't generated by ptrace, let the process handle it by injecting the signal back into the process.
		// If the signal was generated by ptrace, suppress it and send a signal value of 0 instead.
		injectedSig := int(sig)
		if status.Stopped() && isPtraceTrap {
			injectedSig = 0
			if err := p.nextSyscall(pid); err != nil {
				errChan <- fmt.Errorf("failed to process syscall: %w", err)

			}
		}

		// Resume the process with the injected signal value.
		if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
			errChan <- fmt.Errorf("failed to resume process with signal %d: %w", injectedSig, err)
			log.Debugf("(tracing) got error from ptrace syscall: %v", err)
		}
	}
}

// nextSyscall handles the next system call for the given process ID.
func (p *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := p.handleSyscall(pid, regs); err != nil {
			return err
		}
	}

	return nil
}

func (p *ptraceContext) handleExeCve(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	program, err := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
	if err == nil {
		procInfo.Program = program
	}

	exeLocation := fmt.Sprintf("/proc/%d/exe", procInfo.ProcessID)
	exeLocation, err = filepath.EvalSymlinks(exeLocation)
	if err != nil {
		return err
	}

	commLocation := fmt.Sprintf("/proc/%d/comm", procInfo.ProcessID)
	commLocation, err = filepath.EvalSymlinks(commLocation)
	if err != nil {
		return err
	}

	envinLocation := fmt.Sprintf("/proc/%d/environ", procInfo.ProcessID)
	envinLocation, err = filepath.EvalSymlinks(envinLocation)
	if err != nil {
		return err
	}

	cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", procInfo.ProcessID)
	cmdlineLocation, err = filepath.EvalSymlinks(cmdlineLocation)
	if err != nil {
		return err
	}

	status := fmt.Sprintf("/proc/%d/status", procInfo.ProcessID)
	status, err = filepath.EvalSymlinks(status)
	if err != nil {
		return err
	}

	// read status file and set attributes on success
	statusFile, err := os.ReadFile(status)
	if err == nil {
		procInfo.SpecBypassIsVuln = getSpecBypassIsVulnFromStatus(statusFile)
		ppid, err := getPPIDFromStatus(statusFile)
		if err == nil {
			procInfo.ParentPID = ppid
		}
	}

	comm, err := os.ReadFile(commLocation)
	if err == nil {
		procInfo.Comm = cleanString(string(comm))
	}

	environ, err := os.ReadFile(envinLocation)
	if err == nil {
		allVars := strings.Split(string(environ), "\x00")
		filteredEnviron := make([]string, 0)
		environment.FilterEnvironmentArray(allVars, p.environmentBlockList, func(_, _, varStr string) {
			filteredEnviron = append(filteredEnviron, varStr)
		})

		procInfo.Environ = strings.Join(filteredEnviron, " ")
	}

	cmdline, err := os.ReadFile(cmdlineLocation)
	if err == nil {
		procInfo.Cmdline = cleanString(string(cmdline))
	}

	exeDigest, err := cryptoutil.CalculateDigestSetFromFile(exeLocation, p.hash)
	if err == nil {
		procInfo.ExeDigest = exeDigest
	}

	if program != "" {
		programDigest, err := cryptoutil.CalculateDigestSetFromFile(program, p.hash)
		if err == nil {
			procInfo.ProgramDigest = programDigest
		}
	}

	return nil
}

func (p *ptraceContext) handleOpenedFile(pid int, argArray []uintptr) error {
	fileName, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
	if err != nil {
		return err
	}

	procInfo := p.getProcInfo(pid)

	file, err := filepath.EvalSymlinks(fileName)
	//record that the process tried to open the file, even if it doesn't exist
	if err != nil && os.IsNotExist(err) {
		procInfo.OpenedFiles[fileName] = cryptoutil.DigestSet{}
		return nil
	}
	if err != nil {
		return err
	}

	digestSet, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
	if err != nil {
		return err
	}
	procInfo.OpenedFiles[file] = digestSet

	return nil
}

func (p *ptraceContext) handleOpenedSocket(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	domain := int(argArray[0])
	socketType := int(argArray[1])
	protocol := int(argArray[2])

	// Convert domain, socketType, and protocol to human-readable strings
	domainStr, ok := socketDomains[domain]
	if !ok {
		domainStr = fmt.Sprintf("Unknown (%d)", domain)
	}

	typeStr, ok := socketTypes[socketType]
	if !ok {
		typeStr = fmt.Sprintf("Unknown (%d)", socketType)
	}

	protocolStr, ok := socketProtocols[protocol]
	if !ok {
		protocolStr = fmt.Sprintf("Unknown (%d)", protocol)
	}

	// Record the socket's domain, type, and protocol
	socketInfo := SocketInfo{Domain: domainStr, Type: typeStr, Protocol: protocolStr}
	procInfo.OpenedSockets = append(procInfo.OpenedSockets, socketInfo)

	return nil
}

func (p *ptraceContext) handleConnectedSocket(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	sockaddrPtr := argArray[1]
	sockaddrLen := int(argArray[2])

	// Read the sockaddr structure from the traced process's memory
	sockaddrBytes, err := p.readSyscallData(pid, uintptr(sockaddrPtr), sockaddrLen)
	if err != nil {
		return err
	}

	// Parse the bytes manually to get the remote address and port using an inline struct
	sockaddr := struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
	}{}

	if err := binary.Read(bytes.NewReader(sockaddrBytes), binary.LittleEndian, &sockaddr); err != nil {
		return err
	}

	// Get protocol and domain
	var protocol string
	switch sockaddr.Family {
	case syscall.AF_INET:
		protocol = "tcp"
	case syscall.AF_INET6:
		protocol = "tcp6"
	case syscall.AF_UNIX:
		protocol = "unix"
	default:
		return fmt.Errorf("unknown protocol family %d", sockaddr.Family)
	}

	ip := fmt.Sprintf("%d.%d.%d.%d", sockaddr.Addr[0], sockaddr.Addr[1], sockaddr.Addr[2], sockaddr.Addr[3])
	port := int(sockaddr.Port)

	// Record the remote address and port
	connInfo := ConnectionInfo{Protocol: protocol, Address: ip, Port: port}

	// Determine if the socket file is a symlink and resolve it to obtain the actual file path
	if protocol == "unix" {
		path := string(sockaddr.Addr[:])
		if filepath.IsAbs(path) {
			// Ensure the path is not empty
			if len(path) > 0 && path[0] == '\x00' {
				path = path[1:]
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
		}
		connInfo.Address = path
	}

	procInfo.OpenedConnections = append(procInfo.OpenedConnections, connInfo)

	return nil
}

func (p *ptraceContext) handleSyscall(pid int, regs unix.PtraceRegs) error {
	argArray := getSyscallArgs(regs)
	syscallId := getSyscallId(regs)

	switch syscallId {
	case unix.SYS_EXECVE:
		if err := p.handleExeCve(pid, argArray); err != nil {
			return err
		}

	case unix.SYS_OPENAT:
		if err := p.handleOpenedFile(pid, argArray); err != nil {
			return err
		}

	case unix.SYS_SOCKET:
		if err := p.handleOpenedSocket(pid, argArray); err != nil {
			return err
		}
	case unix.SYS_CONNECT:
		if err := p.handleConnectedSocket(pid, argArray); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *ptraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := ctx.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}

		ctx.processes[pid] = procInfo
	}

	return procInfo
}

func (ctx *ptraceContext) procInfoArray() []ProcessInfo {
	processes := make([]ProcessInfo, 0)
	for _, procInfo := range ctx.processes {
		processes = append(processes, *procInfo)
	}

	return processes
}

func (ctx *ptraceContext) readSyscallReg(pid int, addr uintptr, n int) (string, error) {
	data := make([]byte, n)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(n),
	}

	removeIov := unix.RemoteIovec{
		Base: addr,
		Len:  n,
	}

	// ProcessVMReadv is much faster than PtracePeekData since it doesn't route the data through kernel space,
	// but there may be times where this doesn't work.  We may want to fall back to PtracePeekData if this fails
	numBytes, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{removeIov}, 0)
	if err != nil {
		return "", err
	}

	if numBytes == 0 {
		return "", nil
	}

	// don't want to use cgo... look for the first 0 byte for the end of the c string
	size := bytes.IndexByte(data, 0)
	return string(data[:size]), nil
}

func cleanString(s string) string {
	return strings.TrimSpace(strings.Replace(s, "\x00", " ", -1))
}

func getPPIDFromStatus(status []byte) (int, error) {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "PPid:") {
			parts := strings.Split(line, ":")
			ppid := strings.TrimSpace(parts[1])
			return strconv.Atoi(ppid)
		}
	}

	return 0, nil
}

func getSpecBypassIsVulnFromStatus(status []byte) bool {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Speculation_Store_Bypass:") {
			parts := strings.Split(line, ":")
			isVuln := strings.TrimSpace(parts[1])
			if strings.Contains(isVuln, "vulnerable") {
				return true
			}
		}
	}

	return false
}

func (p *ptraceContext) readSyscallData(pid int, addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	n := 0
	for n < size {
		word := make([]byte, WORD_SIZE)
		_, err := unix.PtracePeekData(pid, uintptr(addr)+uintptr(n), word)
		if err != nil {
			return nil, err
		}

		// copy the word into the output buffer, taking care not to over-read
		bytesToCopy := size - n
		if bytesToCopy > WORD_SIZE {
			bytesToCopy = WORD_SIZE
		}
		copy(buf[n:n+bytesToCopy], word[:bytesToCopy])

		n += bytesToCopy
	}

	return buf, nil
}

var socketDomains = map[int]string{
	syscall.AF_UNSPEC: "AF_UNSPEC",
	syscall.AF_UNIX:   "AF_UNIX",
	syscall.AF_INET:   "AF_INET",
	syscall.AF_INET6:  "AF_INET6",
}

var socketTypes = map[int]string{
	syscall.SOCK_STREAM:    "SOCK_STREAM",
	syscall.SOCK_DGRAM:     "SOCK_DGRAM",
	syscall.SOCK_RAW:       "SOCK_RAW",
	syscall.SOCK_RDM:       "SOCK_RDM",
	syscall.SOCK_SEQPACKET: "SOCK_SEQPACKET",
}

var socketProtocols = map[int]string{
	syscall.IPPROTO_IP:   "IPPROTO_IP",
	syscall.IPPROTO_ICMP: "IPPROTO_ICMP",
	syscall.IPPROTO_TCP:  "IPPROTO_TCP",
	syscall.IPPROTO_UDP:  "IPPROTO_UDP",
}
