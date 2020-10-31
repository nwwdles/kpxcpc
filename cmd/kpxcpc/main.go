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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitlab.com/nwwdles/kpxcpc/pkg/client"
)

type Association struct {
	IDKey client.Base64Bytes `json:"idKey"`
	ID    string             `json:"id"`
}

func (a *Association) saveToFile(fname string) (err error) {
	b, err := json.Marshal(a)
	if err != nil {
		return
	}

	if fname == "" || fname == "-" {
		fname = "/dev/stdout"
	}

	// make parent dirs if they don't exist
	if err = os.Mkdir(filepath.Dir(fname), 0o700); err != nil {
		log.Println("info:", err)
	}

	return ioutil.WriteFile(fname, b, 0o600)
}

func initAssociation(r io.Reader) (a Association, err error) {
	if err = json.NewDecoder(r).Decode(&a); err == nil {
		return
	}

	// generate new key if we can't read from file
	idKey, err := client.Nonce()
	if err != nil {
		return
	}

	a.IDKey = idKey[:]

	return
}

type Opts struct {
	sockets         []string
	associationFile string
	format          string
	printJSON       bool
	associateOnly   bool
	waitForUnlock   bool
	triggerUnlock   bool
	totp            bool
}

type App struct {
	opts   Opts
	client *client.Client
}

func New(o Opts) (a *App, err error) {
	var conn net.Conn

	for _, s := range o.sockets {
		if conn, err = net.Dial("unix", s); err != nil {
			continue
		}
	}

	if err != nil {
		return
	}

	var r io.Reader

	switch {
	case o.associateOnly: // reader stays nil to generate a new association.
		r = bytes.NewReader(nil)
		o.associationFile = "/dev/stdout"
	case o.associationFile == "-":
		r = os.Stdin
	default:
		r, err = os.Open(o.associationFile)
		if err != nil {
			_ = err // file is allowed to not exist
		}
	}

	as, err := initAssociation(r)
	if err != nil {
		return
	}

	// We can't simply cast []byte to *[24]byte
	idKey := &[24]byte{}
	copy(idKey[:], as.IDKey)

	c, err := client.New(conn, idKey, as.ID)
	if err != nil {
		return
	}

	a = &App{client: c, opts: o}

	if err = a.connectAndSaveIdentity(); err != nil {
		return
	}

	return a, err
}

func (a *App) connectAndSaveIdentity() (err error) {
	triggerUnlock := a.opts.triggerUnlock

	for {
		if _, err = a.client.ChangePublicKeys(); err != nil {
			return
		}

		if _, err = a.client.TestAssociate(triggerUnlock); err == nil {
			return // OK! we're associated and connected
		}

		// Sometimes key exchange fails and we can't decrypt the messages.
		// This can be fixed by exchanging keys again.
		// TODO: find out why this is happening
		if errors.Is(err, client.ErrCantDecrypt) {
			continue
		}

		// If we're associated and the DB is closed, we try again later.
		// (We get a new keypair but it keeps code shorter).
		_, ident := a.client.AssociationData()
		if a.opts.waitForUnlock && errors.Is(err, client.ErrDBNotOpen) && ident != "" {
			fmt.Fprintf(os.Stderr, "Waiting for DB to be unlocked...\r")
			time.Sleep(time.Second)

			// we don't want keepass window to try to steal the focus each second
			triggerUnlock = false

			continue
		}

		// If all's fine, we get a new identity key and save it.
		// Failing after this point is unexpected, so we don't retry.
		if _, err = a.client.Associate(); err != nil {
			return
		}

		idkey, ident := a.client.AssociationData()
		as := &Association{
			IDKey: idkey[:],
			ID:    ident,
		}

		return as.saveToFile(a.opts.associationFile)
	}
}

func (a *App) printTOTP(uuid string) (err error) {
	totp, err := a.client.GetTOTP(uuid)
	if err != nil {
		return
	}

	switch {
	case a.opts.printJSON:
		return json.NewEncoder(os.Stdout).Encode(totp)
	default:
		fmt.Println(totp.TOTP)
		return
	}
}

func (a *App) printEntry(u string) (err error) {
	logins, err := a.client.GetLogins(u)
	if err != nil {
		return
	}

	switch {
	case a.opts.printJSON:
		return json.NewEncoder(os.Stdout).Encode(logins.Entries)
	default:
		entriesPrintf(a.opts.format, logins.Entries)
		return
	}
}

func entriesPrintf(format string, entries []client.LoginEntry) {
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

		fmt.Print(strings.NewReplacer(replacePairs...).Replace(format))
	}
}

func main() {
	o := Opts{
		waitForUnlock: true,
		triggerUnlock: true,
	}

	datahome := os.Getenv("XDG_DATA_HOME")
	if datahome == "" {
		datahome = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}

	socket := flag.String("socket", "", "path to keepassxc-proxy socket")
	flag.StringVar(&o.associationFile, "identity", filepath.Join(datahome, "kpxcpc", "identity.json"), "set identity file")
	flag.BoolVar(&o.printJSON, "json", false, "print json")
	flag.BoolVar(&o.associateOnly, "associate", false, "associate and print association info to stdout in json format")
	flag.BoolVar(&o.totp, "totp", false, "get TOTP")
	flag.StringVar(&o.format, "fmt", "%p",
		"format string for entry fields: name - %n, login - %l, pass - %p,\n  uuid - %u, custom fields - %F:fieldname\n  ")
	flag.Parse()

	if *socket == "" {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		o.sockets = []string{
			filepath.Join(runtimeDir, "kpxc_server"),
			filepath.Join(runtimeDir, "org.keepassxc.KeePassXC.BrowserServer"),
		}
	} else {
		o.sockets = []string{*socket}
	}

	// try to expand \n \t, etc in the format strings
	if !o.printJSON {
		var err error

		o.format, err = strconv.Unquote(`"` + strings.ReplaceAll(o.format, `"`, `\"`) + `"`)
		if err != nil {
			log.Fatalln(err)
		}
	}

	app, err := New(o)
	if err != nil {
		log.Fatalln(err)
	}

	switch {
	case o.associateOnly:
		return
	case o.totp:
		uuids := flag.Args()
		if len(uuids) == 0 {
			log.Fatalln("Please provide at least one entry UUID")
		}

		for _, u := range uuids {
			if err = app.printTOTP(u); err != nil {
				// Note: currently it seems like keepass silently fails with
				// `"success": "true"` if no entry exists/no totp is set up.
				log.Fatalln(err)
			}
		}
	default:
		urls := flag.Args()
		if len(urls) == 0 {
			log.Fatalln("Please provide at least one URL argument.")
		}

		for _, u := range urls {
			if err = app.printEntry(u); err != nil {
				if errors.Is(err, client.ErrNoLoginsFound) {
					log.Fatalf("No logins found for %s\n", u)
				}

				log.Fatalln(err)
			}
		}
	}
}
