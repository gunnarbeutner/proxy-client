package main

import (
	"fmt"
	"github.com/gunnarbeutner/gssapi"
	"github.com/gunnarbeutner/gssapi/spnego"
	"github.com/jessevdk/go-flags"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

var opts struct {
	Proxy  string `short:"P" long:"proxy" description:"Proxy address (host:port)" required:"true"`
	Target string `short:"T" long:"target" description:"Target address (host:port)" required:"true"`
}

var (
	lib *gssapi.Lib
	ctx *gssapi.CtxId
)

func initSecContext(host string, challenge *gssapi.Buffer) (*gssapi.Buffer, error) {
	nameBuf, err := lib.MakeBufferString(fmt.Sprintf("HTTP/%s", host))
	if err != nil {
		panic(err)
	}

	serviceName, err := nameBuf.Name(lib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		panic(err)
	}

	var token *gssapi.Buffer
	ctx, _, token, _, _, err = lib.InitSecContext(
		lib.GSS_C_NO_CREDENTIAL,
		ctx,
		serviceName,
		lib.GSS_MECH_SPNEGO,
		0,
		0,
		lib.GSS_C_NO_CHANNEL_BINDINGS,
		challenge)

	switch err {
	case nil:
		return token, nil
	case gssapi.ErrContinueNeeded:
		return token, nil
	default:
		return nil, err
	}
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	lib, err = gssapi.Load(nil)
	if err != nil {
		log.Fatal(err)
	}

	tcpConn, err := net.Dial("tcp", opts.Proxy)
	if err != nil {
		log.Fatal(err)
	}

	conn := httputil.NewClientConn(tcpConn, nil)

	host := strings.Split(opts.Proxy, ":")[0]

	ctx = lib.GSS_C_NO_CONTEXT
	challenge := lib.GSS_C_NO_BUFFER

	for {
		token, err := initSecContext(host, challenge)
		challenge.Release()
		if err != nil {
			gssErr, ok := err.(*gssapi.Error)
			if ok && gssErr.Major == gssapi.GSS_S_BAD_MECH {
				log.Fatal("Could not find usable Kerberos ticket - your TGT may have expired (hint: try kinit)")
			} else {
				log.Fatal(err)
			}
		}

		request := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: opts.Target},
			Host:   opts.Target,
			Header: make(http.Header),
		}

		spnego.AddSPNEGONegotiate(request.Header, "Authorization", token)
		token.Release()

		err = conn.Write(request)
		if err != nil {
			log.Fatal(err)
		}

		response, err := conn.Read(request)
		if err != nil {
			log.Fatal(err)
		}

		ok, newChallenge := spnego.CheckSPNEGONegotiate(lib, response.Header, "Www-Authenticate")
		if ok {
			challenge = newChallenge
		}

		if response.StatusCode != 401 {
			break
		}
	}

	_, reader := conn.Hijack()

	go io.Copy(tcpConn, os.Stdin)
	io.Copy(os.Stdout, reader)
}
