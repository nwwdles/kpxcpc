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
	"io/ioutil"
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

func saveAssociation(fname string, c *client.Client) (err error) {
	idkey, ident := c.GetAssociation()
	a := &Association{
		IDKey: idkey[:],
		ID:    ident,
	}

	b, err := json.Marshal(a)
	if err != nil {
		return
	}

	err = os.Mkdir(filepath.Dir(fname), 0o700)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return
		}
	}

	err = ioutil.WriteFile(fname, b, 0o600)
	if err != nil {
		return
	}

	return
}

func initClient(socketpath, fname string) (c *client.Client, err error) {
	conn, err := net.Dial("unix", socketpath)
	if err != nil {
		return
	}

	idKey, err := client.Nonce()
	if err != nil {
		return
	}

	a := &Association{IDKey: idKey[:]}

	b, err := ioutil.ReadFile(fname)
	if err == nil {
		err = json.Unmarshal(b, a)
		if err != nil {
			return // corrupted file?
		}
	}

	k := &[24]byte{}
	copy(k[:], a.IDKey)

	return client.New(conn, k, a.ID)
}

func connectAndSaveIdentity(c *client.Client, fname string, waitForUnlock, triggerUnlock bool) (err error) {
	for {
		if _, err = c.ChangePublicKeys(); err != nil {
			return
		}

		if _, err = c.TestAssociate(triggerUnlock); err == nil {
			return // we're associated and connected
		}

		// Sometimes key exchange fails and we can't decrypt the messages.
		// This can be fixed by exchanging keys again.
		// TODO: find out why this is happening
		if errors.Is(err, client.ErrCantDecrypt) {
			continue
		}

		// If we're associated and the DB is closed, we try again later.
		// (We get a new keypair but it keeps code shorter).
		_, n := c.GetAssociation()
		if waitForUnlock && errors.Is(err, client.ErrDBNotOpen) && n != "" {
			fmt.Fprintf(os.Stderr, "Waiting for DB to be unlocked...\r")
			time.Sleep(time.Second)

			// we don't want keepass window to try to steal the focus each second
			triggerUnlock = false

			continue
		}

		// If all's fine, we get a new identity key and save it.
		// Failing after this point is unexpected, so we don't retry.
		if _, err = c.Associate(); err != nil {
			return
		}

		return saveAssociation(fname, c)
	}
}

func entriesJSONPrint(entries []client.LoginEntry) {
	b, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
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

// unquote expands escape characters like `\n` into actual characters.
// it can be done by the user but posix sh doesn't have $'\n' and using "$(printf '\n')"
// or actual newlines is not always desirable.
func unquote(s string) (string, error) {
	return strconv.Unquote(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
}

func main() {
	datahome := os.Getenv("XDG_DATA_HOME")
	if datahome == "" {
		datahome = os.Getenv("HOME") + "/.local/share"
	}

	identityFile := flag.String("identity", datahome+"/kpxcpc/identity.json",
		"set identity file")
	printJSON := flag.Bool("json", false,
		"print json")
	socket := flag.String("socket", os.Getenv("XDG_RUNTIME_DIR")+"/kpxc_server",
		"path to keepassxc-proxy socket")
	format := flag.String("fmt", `%p`,
		`format string for main entry fields: name - %n, login - %l, pass - %p,
  uuid - %u, fields - %F:fieldname
`)

	flag.Parse()

	urls := flag.Args()

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "Please provide at least one URL argument.")

		return
	}

	c, err := initClient(*socket, *identityFile)
	if err != nil {
		panic(err)
	}

	waitForUnlock := true
	triggerUnlock := true

	if err = connectAndSaveIdentity(c, *identityFile, waitForUnlock, triggerUnlock); err != nil {
		panic(err)
	}

	var logins client.GetLoginsResponseMessage

	logins, err = c.GetLogins(urls[0])
	if err != nil {
		if errors.Is(err, client.ErrNoLoginsFound) {
			fmt.Fprintln(os.Stderr, "No logins found.")
			os.Exit(1)
		}

		panic(err)
	}

	if *printJSON {
		entriesJSONPrint(logins.Entries)
		return
	}

	// try to expand \n \t, etc in the format strings
	*format, err = unquote(*format)
	if err != nil {
		panic(err)
	}

	entriesPrintf(*format, logins.Entries)
}
