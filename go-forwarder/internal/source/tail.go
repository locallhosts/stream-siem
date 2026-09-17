package source

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// FileSource tails a log file by polling, following rotation. We poll rather
// than use inotify/fsnotify so the same code works unmodified across
// container filesystems (overlay/bind mounts) where inotify events on
// rotated files are unreliable. Rotation is detected by comparing the
// current file's inode to the one we have open; if it changed (rename+
// recreate, or truncate to a smaller size), we reopen from the start.
type FileSource struct {
	Path          string
	SourceTypeTag string
	NodeID        string
	FromBeginning bool

	PollInterval time.Duration // default 500ms if zero
}

func (f *FileSource) Name() string { return fmt.Sprintf("file:%s", f.Path) }

func (f *FileSource) Run(out chan<- Event, errs chan<- error, stop <-chan struct{}) {
	poll := f.PollInterval
	if poll == 0 {
		poll = 500 * time.Millisecond
	}

	file, reader, inode, offset, err := f.openAt(f.FromBeginning)
	for err != nil {
		// File may not exist yet (e.g. service not started). Retry until
		// stop is signalled rather than exiting the source permanently.
		select {
		case <-stop:
			return
		case <-time.After(poll):
		}
		file, reader, inode, offset, err = f.openAt(f.FromBeginning)
	}
	defer file.Close()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			for {
				line, readErr := reader.ReadString('\n')
				if len(line) > 0 {
					trimmed := trimNewline(line)
					if trimmed != "" {
						out <- Event{
							SourceType: f.SourceTypeTag,
							Host:       f.NodeID,
							ReceivedAt: time.Now().UTC(),
							Raw:        trimmed,
						}
					}
					offset += int64(len(line))
				}
				if readErr != nil {
					if readErr != io.EOF {
						errs <- fmt.Errorf("%s: read: %w", f.Name(), readErr)
					}
					break
				}
			}

			// Check for rotation: inode changed, or file shrank (truncated
			// in place, e.g. by `> file` or logrotate's copytruncate mode).
			st, statErr := os.Stat(f.Path)
			if statErr != nil {
				continue // transient; file may be mid-rotation
			}
			newInode := inodeOf(st)
			shrank := st.Size() < offset
			if newInode != inode || shrank {
				file.Close()
				newFile, newReader, newInodeVal, newOffset, openErr := f.openAt(true)
				if openErr != nil {
					errs <- fmt.Errorf("%s: reopen after rotation: %w", f.Name(), openErr)
					continue
				}
				file, reader, inode, offset = newFile, newReader, newInodeVal, newOffset
			}
		}
	}
}

func (f *FileSource) openAt(fromBeginning bool) (*os.File, *bufio.Reader, uint64, int64, error) {
	file, err := os.Open(f.Path)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	var offset int64
	if !fromBeginning {
		st, err := file.Stat()
		if err == nil {
			offset = st.Size()
		}
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			return nil, nil, 0, 0, err
		}
	}
	st, _ := file.Stat()
	return file, bufio.NewReader(file), inodeOf(st), offset, nil
}

func inodeOf(st os.FileInfo) uint64 {
	if st == nil {
		return 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}

func trimNewline(s string) string {
	n := len(s)
	if n > 0 && s[n-1] == '\n' {
		n--
	}
	if n > 0 && s[n-1] == '\r' {
		n--
	}
	return s[:n]
}
