package main

import (
	"debug/pe"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/exp/slices"
)

// "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" verify  /pa "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
func ExtractDigitalSignature(filePath string) (buf []byte, err error) {
	pefile, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer pefile.Close()

	var vAddr uint32
	var size uint32
	switch t := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		vAddr = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		size = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	case *pe.OptionalHeader64:
		vAddr = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		size = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	}

	if vAddr <= 0 || size <= 0 {
		return nil, errors.New("Not signed PE file")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf = make([]byte, int64(size))
	f.ReadAt(buf, int64(vAddr+8))

	return buf, nil
}
func killProcs() {
	WHITE_LIST := []string{
		"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2209.6.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe",
	}
	procs, _ := process.Processes()
	for _, proc := range procs {
		createTime, _ := proc.CreateTime()
		if time.Since(time.UnixMilli(createTime)) < time.Second*60 {
			pid := int(proc.Pid)
			if os.Getpid() == pid || os.Getppid() == pid {
				continue
			}
			p, err := os.FindProcess(pid)
			if err != nil {
				continue
			}
			name, _ := proc.Name()
			fullPath, _ := proc.Exe()
			// sig, err := ExtractDigitalSignature(fullPath)
			// fmt.Printf("sig: %v, err: %v\n", sig, err)
			if slices.Contains(WHITE_LIST, fullPath) {
				fmt.Printf("white list %d(%s)[%s]\n", p.Pid, name, fullPath)
			} else {
				fmt.Printf("ready to kill %d(%s)[%s]\n", p.Pid, name, fullPath)
				// if err := p.Signal(os.Kill); err != nil {
				// 	panic(err)
				// }
			}
		}
	}
}

func main() {
	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Println("event:", event)
				if event.Has(fsnotify.Write) {
					log.Println("modified file:", event.Name)
					killProcs()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(os.ExpandEnv("C:\\Users\\$USERNAME\\Documents\\"))
	if err != nil {
		log.Fatal(err)
	}

	// Block main goroutine forever.
	<-make(chan struct{})
}
