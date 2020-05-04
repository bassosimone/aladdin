/*
 * Copyright (c) 2015, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
/*
 * Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package upstreamproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// httpProxy is a HTTP connect proxy.
type httpProxy struct {
	hostPort      string
	username      string
	password      string
	forward       proxy.Dialer
	customHeaders http.Header
}

func newHTTP(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	hp := new(httpProxy)
	hp.hostPort = uri.Host
	hp.forward = forward
	if uri.User != nil {
		hp.username = uri.User.Username()
		hp.password, _ = uri.User.Password()
	}

	if upstreamProxyConfig, ok := forward.(*UpstreamProxyConfig); ok {
		hp.customHeaders = upstreamProxyConfig.CustomHeaders
	}

	return hp, nil
}

func (hp *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the http client connection.
	pc := &proxyConn{
		authState:     HTTP_AUTH_STATE_UNCHALLENGED,
		dialFn:        hp.forward.Dial,
		proxyAddr:     hp.hostPort,
		customHeaders: hp.customHeaders,
	}
	err := pc.makeNewClientConn()
	if err != nil {
		// Already wrapped in proxyError
		return nil, err
	}

handshakeLoop:
	for {
		err := pc.handshake(addr, hp.username, hp.password)
		if err != nil {
			// Already wrapped in proxyError
			return nil, err
		}
		switch pc.authState {
		case HTTP_AUTH_STATE_SUCCESS:
			pc.hijackedConn, pc.staleReader = pc.httpClientConn.Hijack()
			return pc, nil
		case HTTP_AUTH_STATE_CHALLENGED:
			continue
		default:
			break handshakeLoop
		}
	}
	return nil, proxyError(fmt.Errorf("unknown handshake error in state %v", pc.authState))
}

type proxyConn struct {
	dialFn         DialFunc
	proxyAddr      string
	customHeaders  http.Header
	httpClientConn *httputil.ClientConn //lint:ignore SA1019 httputil.ClientConn used for client-side hijack
	hijackedConn   net.Conn
	staleReader    *bufio.Reader
	authResponse   *http.Response
	authState      HttpAuthState
	authenticator  HttpAuthenticator
}

func (pc *proxyConn) handshake(addr, username, password string) error {
	// HACK: prefix addr of the form 'hostname:port' with a 'http' scheme
	// so it could be parsed by url.Parse
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return proxyError(fmt.Errorf("failed to parse proxy address: %v", err))
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return proxyError(fmt.Errorf("create proxy request: %v", err))
	}
	req.Close = false
	req.Header.Set("User-Agent", "")

	for k, s := range pc.customHeaders {
		// handle special Host header case
		if k == "Host" {
			if len(s) > 0 {
				// hack around 'CONNECT' special case:
				// https://golang.org/src/net/http/request.go#L476
				// using URL.Opaque, see URL.RequestURI() https://golang.org/src/net/url/url.go#L915
				req.URL.Opaque = req.Host
				req.URL.Path = " "
				req.Host = s[0]
			}
		} else {
			req.Header[k] = s
		}
	}

	if pc.authState == HTTP_AUTH_STATE_CHALLENGED {
		err := pc.authenticator.Authenticate(req, pc.authResponse)
		if err != nil {
			pc.authState = HTTP_AUTH_STATE_FAILURE
			// Already wrapped in proxyError
			return err
		}
	}

	resp, err := pc.httpClientConn.Do(req)

	//lint:ignore SA1019 httputil.ClientConn used for client-side hijack
	errPersistEOF := httputil.ErrPersistEOF

	if err != nil && err != errPersistEOF {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return proxyError(fmt.Errorf("making proxy request: %v", err))
	}

	if resp.StatusCode == 200 {
		pc.authState = HTTP_AUTH_STATE_SUCCESS
		return nil
	}

	if resp.StatusCode == 407 {
		if pc.authState == HTTP_AUTH_STATE_UNCHALLENGED {
			var authErr error
			pc.authenticator, authErr = NewHttpAuthenticator(resp, username, password)
			if authErr != nil {
				pc.httpClientConn.Close()
				pc.authState = HTTP_AUTH_STATE_FAILURE
				// Already wrapped in proxyError
				return authErr
			}
		}

		pc.authState = HTTP_AUTH_STATE_CHALLENGED
		pc.authResponse = resp
		if username == "" {
			pc.httpClientConn.Close()
			pc.authState = HTTP_AUTH_STATE_FAILURE
			return proxyError(fmt.Errorf("ho username credentials provided for proxy auth"))
		}
		if err == errPersistEOF {
			// The server may send Connection: close,
			// at this point we just going to create a new
			// ClientConn and continue the handshake
			err = pc.makeNewClientConn()
			if err != nil {
				// Already wrapped in proxyError
				return err
			}
		}
		return nil
	}
	pc.authState = HTTP_AUTH_STATE_FAILURE
	return proxyError(fmt.Errorf("handshake error: %v, response status: %s", err, resp.Status))
}

func (pc *proxyConn) makeNewClientConn() error {
	c, err := pc.dialFn("tcp", pc.proxyAddr)
	if pc.httpClientConn != nil {
		pc.httpClientConn.Close()
	}
	if err != nil {
		return proxyError(fmt.Errorf("makeNewClientConn: %v", err))
	}
	//lint:ignore SA1019 httputil.ClientConn used for client-side hijack
	pc.httpClientConn = httputil.NewClientConn(c, nil)
	return nil
}

func (pc *proxyConn) Read(b []byte) (int, error) {
	if pc.staleReader != nil {
		if pc.staleReader.Buffered() > 0 {
			return pc.staleReader.Read(b)
		}
		pc.staleReader = nil
	}
	return pc.hijackedConn.Read(b)
}

func (pc *proxyConn) Write(b []byte) (int, error) {
	return pc.hijackedConn.Write(b)
}

func (pc *proxyConn) Close() error {
	return pc.hijackedConn.Close()
}

func (pc *proxyConn) LocalAddr() net.Addr {
	return pc.hijackedConn.LocalAddr()
}

// RemoteAddr returns the network address of the proxy that
// the proxyConn is connected to.
func (pc *proxyConn) RemoteAddr() net.Addr {
	// Note: returning nil here can crash "tls".
	return pc.hijackedConn.RemoteAddr()
}

func (pc *proxyConn) SetDeadline(t time.Time) error {
	return proxyError(fmt.Errorf("not supported"))
}

func (pc *proxyConn) SetReadDeadline(t time.Time) error {
	return proxyError(fmt.Errorf("not supported"))
}

func (pc *proxyConn) SetWriteDeadline(t time.Time) error {
	return proxyError(fmt.Errorf("not supported"))
}

func init() {
	proxy.RegisterDialerType("http", newHTTP)
}
