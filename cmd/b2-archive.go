package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/strangeoceans/b2-archive/pkg/b2"
	"github.com/strangeoceans/b2-archive/pkg/crypt"
)

const helpText string = "b2-archive <target> <bucket> <num>\nKeep <num> " +
	"most recently modified files in <target>, transferring all others to B2 <bucket>"

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "--help" {
		return fmt.Errorf(helpText)
	}
	if len(args) != 3 {
		return fmt.Errorf("invalid operands\n\n%s", helpText)
	}
	dir, bucketName, n := args[0], args[1], args[2]

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("error checking target %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("target `%s` is not a directory\n\n%s", dir, helpText)
	}

	numToKeep, err := strconv.Atoi(n)
	if err != nil || numToKeep < 0 {
		return fmt.Errorf("%d is not a positive integer\n\n%s", numToKeep, helpText)
	}

	keyId, err := os.ReadFile("/run/secrets/b2/strangeoceans-gallery/keyId")
	if err != nil {
		return fmt.Errorf("error reading keyId: %w", err)
	}
	applicationKey, err := os.ReadFile("/run/secrets/b2/strangeoceans-gallery/applicationKey")
	if err != nil {
		return fmt.Errorf("error reading applicationKey: %w", err)
	}
	bucket, _ := b2.New(string(keyId), string(applicationKey), "us-west-004", bucketName)

	passwordFile, err := os.Open("/run/secrets/encryption/password")
	if err != nil {
		return fmt.Errorf("error opening password file: %w", err)
	}
	saltFile, err := bucket.Get("salt")
	if err != nil {
		return fmt.Errorf("error getting salt file: %w", err)
	}
	crypter, err := crypt.New(passwordFile, saltFile)
	if err != nil {
		return fmt.Errorf("error creating crypter: %w", err)
	}

	files, err := getFilesToTransfer(dir, numToKeep)
	if err != nil {
		return err
	}

	var errs error
	for _, file := range files {
		encrypted, err := crypter.Encrypt(file.Src)
		if err != nil {
			file.Src.Close()
			errs = errors.Join(errs, fmt.Errorf("error encrypting file %s: %w", file.Name, err))
		}
		if err := bucket.Put(file.Name, encrypted); err != nil {
			file.Src.Close()
			errors.Join(fmt.Errorf("error putting file %s: %w", file.Name, err))
		}
		file.Src.Close()
		os.Remove(file.SrcPath)
	}
	if errs != nil {
		return errs
	}

	return nil
}

func getFilesToTransfer(target string, numToKeep int) ([]File, error) {
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, fmt.Errorf("error reading directory %s: %w", target, err)
	}

	files := []File{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("error getting info for file %s: %w", entry.Name(), err)
		}
		path := filepath.Join(target, info.Name())
		src, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("error opening file %s: %w", info.Name(), err)
		}
		files = append(files, File{
			Src:     src,
			SrcPath: path,
			Name:    info.Name(),
			ModTime: info.ModTime(),
		})
	}

	slices.SortFunc(files, func(a, b File) int {
		if a.ModTime.Before(b.ModTime) {
			return -1
		}
		if a.ModTime.After(b.ModTime) {
			return 1
		}
		return 0
	})

	return files[:max(0, len(files)-numToKeep)], nil
}

type File struct {
	Src     *os.File
	SrcPath string
	Name    string
	ModTime time.Time
}
