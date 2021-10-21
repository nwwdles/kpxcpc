// The MIT License (MIT)
//
// Copyright (c) 2020 cupnoodles
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitlab.com/nwwdles/kpxcpc/kpclient"
)

var (
	ErrTOTPUUIDRequired = errors.New("entry UUID is required")
	ErrURLRequired      = errors.New("URL argument is required")
)

type Association struct {
	ID    string `json:"id"`
	IDKey []byte `json:"idKey"`
}

type Opts struct {
	associationFile string
	format          string
	sockets         []string
	printJSON       bool
	associateOnly   bool
	waitForUnlock   bool
	triggerUnlock   bool
	totp            bool
}

type App struct {
	client *kpclient.Client
	opts   Opts
}

func (a *App) connect() error {
	var r io.ReadCloser
	switch {
	case a.opts.associateOnly: // reader stays nil to generate a new association.
	case a.opts.associationFile == "-":
		r = os.Stdin
	default:
		if _, err := os.Stat(a.opts.associationFile); err == nil {
			r, err = os.Open(a.opts.associationFile)
			if err != nil {
				return fmt.Errorf("failed to open association info: %w", err)
			}
		}
	}

	var as Association
	if r != nil {
		err := json.NewDecoder(r).Decode(&as)
		if err != nil {
			return fmt.Errorf("failed to decode saved association info: %w", err)
		}
		r.Close()
	}

	var err error
	var conn net.Conn
	for _, s := range a.opts.sockets {
		if conn, err = net.Dial("unix", s); err != nil {
			continue
		}
	}
	if err != nil {
		return fmt.Errorf("error connecting to keepassxc: %w", err)
	}

	a.client, err = kpclient.New(conn, nil, as.IDKey, as.ID)
	if err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}

	triggerUnlock := a.opts.triggerUnlock

	retries := 0
	for {
		if _, err = a.client.ChangePublicKeys(); err != nil {
			return fmt.Errorf("failed to exchange public keys: %w", err)
		}

		if _, err = a.client.TestAssociate(triggerUnlock); err == nil {
			return nil // OK! we're associated and connected
		}

		// Sometimes key exchange fails and we can't decrypt the messages.
		// This can be fixed by exchanging keys again.
		// TODO: find out why this is happening
		if errors.Is(err, kpclient.ErrCannotDecryptMessage) {
			continue
		}

		// If we're associated and the DB is closed, we try again later.
		// (We get a new keypair but it keeps code shorter).
		_, ident := a.client.AssociationData()
		if errors.Is(err, kpclient.ErrDatabaseNotOpened) && ident != "" {
			if !a.opts.waitForUnlock {
				return fmt.Errorf("failed to open database: %w", err)
			}

			fmt.Fprintf(os.Stderr, "waiting for the database to be unlocked... %v\r", retries)
			retries++
			triggerUnlock = false // we don't want keepass window to steal focus every second

			time.Sleep(time.Second)
			continue
		}
		// If all's fine, we get a new identity key and save it.
		// Failing after this point is unexpected, so we don't retry.
		if _, err = a.client.Associate(); err != nil {
			return fmt.Errorf("failed to associate: %w", err)
		}

		return a.saveToFile(a.opts.associationFile)
	}
}

func (a *App) saveToFile(file string) (err error) {
	idkey, ident := a.client.AssociationData()
	as := Association{IDKey: idkey[:], ID: ident}

	var w io.WriteCloser
	if file == "" || file == "-" || a.opts.associateOnly {
		w = os.Stdout
	} else {
		if err = os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			// we may try to ignore the error and hope that WriteFile succeeds anyway
			log.Println("info:", err)
		}

		w, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer w.Close()
	}

	return json.NewEncoder(w).Encode(as)
}

func (a *App) printTOTP(uuid string) (err error) {
	totp, err := a.client.GetTOTP(uuid)
	if err != nil {
		return
	}

	if a.opts.printJSON {
		return json.NewEncoder(os.Stdout).Encode(totp)
	}

	fmt.Print(totp.TOTP)
	return
}

func (a *App) printEntry(u string) error {
	logins, err := a.client.GetLogins(u)
	if err != nil {
		return err
	}

	if a.opts.printJSON {
		return json.NewEncoder(os.Stdout).Encode(logins.Entries)
	}

	fmt.Print(formatEntries(a.opts.format, logins.Entries))
	return err
}

func formatEntries(format string, entries []kpclient.LoginEntry) string {
	var b strings.Builder
	for i := range entries {
		e := &entries[i]
		replacePairs := []string{
			"%%", "%",
			"%n", e.Name,
			"%p", e.Password,
			"%l", e.Login,
			"%u", e.UUID,
		}

		for _, v := range e.StringFields {
			for k, v := range v {
				replacePairs = append(replacePairs, "%F:"+strings.TrimPrefix(k, "KPH: "), v)
			}
		}

		b.WriteString(strings.NewReplacer(replacePairs...).Replace(format))
	}
	return b.String()
}

func (a *App) Run() error {
	err := a.connect()
	if err != nil {
		return err
	}

	switch {
	case a.opts.associateOnly:
		return err
	case a.opts.totp:
		uuids := flag.Args()
		if len(uuids) == 0 {
			return ErrTOTPUUIDRequired
		}

		for _, u := range uuids {
			err = a.printTOTP(u)
			if err != nil {
				// Note: currently it seems like keepass silently fails with
				// `"success": "true"` if no entry exists/no totp is set up.
				return err
			}
		}
	default:
		urls := flag.Args()
		if len(urls) == 0 {
			return ErrURLRequired
		}

		for _, u := range urls {
			if err = a.printEntry(u); err != nil {
				return fmt.Errorf("can't print logins for %s: %w", u, err)
			}
		}
	}
	return nil
}

func main() {
	opts := Opts{}

	datahome := os.Getenv("XDG_DATA_HOME")
	if datahome == "" {
		datahome = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}

	socket := flag.String("socket", "", "path to keepassxc-proxy socket")
	flag.StringVar(&opts.associationFile, "identity", filepath.Join(datahome, "kpxcpc", "identity.json"), "set identity file")
	flag.BoolVar(&opts.printJSON, "json", false, "print json")
	flag.BoolVar(&opts.associateOnly, "associate", false, "associate and print association info to stdout in json format")
	flag.BoolVar(&opts.totp, "totp", false, "get TOTP")
	flag.StringVar(&opts.format, "fmt", "%p",
		"format string for entry fields: name - %n, login - %l, pass - %p,\n  uuid - %u, custom fields - %F:fieldname\n  ")
	nounlock := flag.Bool("nounlock", false, "do not trigger DB unlock prompt")
	flag.Parse()

	opts.triggerUnlock = !*nounlock
	opts.waitForUnlock = !*nounlock

	// try to expand \n \t, etc in the format strings
	if !opts.printJSON {
		var err error

		opts.format, err = strconv.Unquote(`"` + strings.ReplaceAll(opts.format, `"`, `\"`) + `"`)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if *socket == "" {
		// keepassxc changed the socket name in some version
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		opts.sockets = []string{
			filepath.Join(runtimeDir, "kpxc_server"),
			filepath.Join(runtimeDir, "org.keepassxc.KeePassXC.BrowserServer"),
		}
	} else {
		opts.sockets = []string{*socket}
	}

	app := &App{opts: opts}
	if err := app.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
