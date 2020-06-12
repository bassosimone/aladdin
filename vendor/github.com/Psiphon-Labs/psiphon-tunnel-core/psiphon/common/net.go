/*
 * Copyright (c) 2016, Psiphon Inc.
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

package common

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/miekg/dns"
	"github.com/wader/filtertransport"
)

// NetDialer mimicks the net.Dialer interface.
type NetDialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Closer defines the interface to a type, typically a net.Conn, that can be
// closed.
type Closer interface {
	IsClosed() bool
}

// CloseWriter defines the interface to a type, typically a net.TCPConn, that
// implements CloseWrite.
type CloseWriter interface {
	CloseWrite() error
}

// IrregularIndicator defines the interface for a type, typically a net.Conn,
// that detects and reports irregular conditions during initial network
// connection establishment.
type IrregularIndicator interface {
	IrregularTunnelError() error
}

// TerminateHTTPConnection sends a 404 response to a client and also closes
// the persistent connection.
func TerminateHTTPConnection(
	responseWriter http.ResponseWriter, request *http.Request) {

	http.NotFound(responseWriter, request)

	hijack, ok := responseWriter.(http.Hijacker)
	if !ok {
		return
	}
	conn, buffer, err := hijack.Hijack()
	if err != nil {
		return
	}
	buffer.Flush()
	conn.Close()
}

// IPAddressFromAddr is a helper which extracts an IP address
// from a net.Addr or returns "" if there is no IP address.
func IPAddressFromAddr(addr net.Addr) string {
	ipAddress := ""
	if addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ipAddress = host
		}
	}
	return ipAddress
}

// PortFromAddr is a helper which extracts a port number from a net.Addr or
// returns 0 if there is no port number.
func PortFromAddr(addr net.Addr) int {
	port := 0
	if addr != nil {
		_, portStr, err := net.SplitHostPort(addr.String())
		if err == nil {
			port, _ = strconv.Atoi(portStr)
		}
	}
	return port
}

// Conns is a synchronized list of Conns that is used to coordinate
// interrupting a set of goroutines establishing connections, or
// close a set of open connections, etc.
// Once the list is closed, no more items may be added to the
// list (unless it is reset).
type Conns struct {
	mutex    sync.Mutex
	isClosed bool
	conns    map[net.Conn]bool
}

// NewConns initializes a new Conns.
func NewConns() *Conns {
	return &Conns{}
}

func (conns *Conns) Reset() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = false
	conns.conns = make(map[net.Conn]bool)
}

func (conns *Conns) Add(conn net.Conn) bool {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	if conns.isClosed {
		return false
	}
	if conns.conns == nil {
		conns.conns = make(map[net.Conn]bool)
	}
	conns.conns[conn] = true
	return true
}

func (conns *Conns) Remove(conn net.Conn) {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	delete(conns.conns, conn)
}

func (conns *Conns) CloseAll() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = true
	for conn := range conns.conns {
		conn.Close()
	}
	conns.conns = make(map[net.Conn]bool)
}

// LRUConns is a concurrency-safe list of net.Conns ordered
// by recent activity. Its purpose is to facilitate closing
// the oldest connection in a set of connections.
//
// New connections added are referenced by a LRUConnsEntry,
// which is used to Touch() active connections, which
// promotes them to the front of the order and to Remove()
// connections that are no longer LRU candidates.
//
// CloseOldest() will remove the oldest connection from the
// list and call net.Conn.Close() on the connection.
//
// After an entry has been removed, LRUConnsEntry Touch()
// and Remove() will have no effect.
type LRUConns struct {
	mutex sync.Mutex
	list  *list.List
}

// NewLRUConns initializes a new LRUConns.
func NewLRUConns() *LRUConns {
	return &LRUConns{list: list.New()}
}

// Add inserts a net.Conn as the freshest connection
// in a LRUConns and returns an LRUConnsEntry to be
// used to freshen the connection or remove the connection
// from the LRU list.
func (conns *LRUConns) Add(conn net.Conn) *LRUConnsEntry {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	return &LRUConnsEntry{
		lruConns: conns,
		element:  conns.list.PushFront(conn),
	}
}

// CloseOldest closes the oldest connection in a
// LRUConns. It calls net.Conn.Close() on the
// connection.
func (conns *LRUConns) CloseOldest() {
	conns.mutex.Lock()
	oldest := conns.list.Back()
	if oldest != nil {
		conns.list.Remove(oldest)
	}
	// Release mutex before closing conn
	conns.mutex.Unlock()
	if oldest != nil {
		oldest.Value.(net.Conn).Close()
	}
}

// LRUConnsEntry is an entry in a LRUConns list.
type LRUConnsEntry struct {
	lruConns *LRUConns
	element  *list.Element
}

// Remove deletes the connection referenced by the
// LRUConnsEntry from the associated LRUConns.
// Has no effect if the entry was not initialized
// or previously removed.
func (entry *LRUConnsEntry) Remove() {
	if entry.lruConns == nil || entry.element == nil {
		return
	}
	entry.lruConns.mutex.Lock()
	defer entry.lruConns.mutex.Unlock()
	entry.lruConns.list.Remove(entry.element)
}

// Touch promotes the connection referenced by the
// LRUConnsEntry to the front of the associated LRUConns.
// Has no effect if the entry was not initialized
// or previously removed.
func (entry *LRUConnsEntry) Touch() {
	if entry.lruConns == nil || entry.element == nil {
		return
	}
	entry.lruConns.mutex.Lock()
	defer entry.lruConns.mutex.Unlock()
	entry.lruConns.list.MoveToFront(entry.element)
}

// ActivityMonitoredConn wraps a net.Conn, adding logic to deal with
// events triggered by I/O activity.
//
// When an inactivity timeout is specified, the network I/O will
// timeout after the specified period of read inactivity. Optionally,
// for the purpose of inactivity only, ActivityMonitoredConn will also
// consider the connection active when data is written to it.
//
// When a LRUConnsEntry is specified, then the LRU entry is promoted on
// either a successful read or write.
//
// When an ActivityUpdater is set, then its UpdateActivity method is
// called on each read and write with the number of bytes transferred.
// The durationNanoseconds, which is the time since the last read, is
// reported only on reads.
//
type ActivityMonitoredConn struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	monotonicStartTime   int64
	lastReadActivityTime int64
	realStartTime        time.Time
	net.Conn
	inactivityTimeout time.Duration
	activeOnWrite     bool
	activityUpdater   ActivityUpdater
	lruEntry          *LRUConnsEntry
}

// ActivityUpdater defines an interface for receiving updates for
// ActivityMonitoredConn activity. Values passed to UpdateProgress are
// bytes transferred and conn duration since the previous UpdateProgress.
type ActivityUpdater interface {
	UpdateProgress(bytesRead, bytesWritten int64, durationNanoseconds int64)
}

// NewActivityMonitoredConn creates a new ActivityMonitoredConn.
func NewActivityMonitoredConn(
	conn net.Conn,
	inactivityTimeout time.Duration,
	activeOnWrite bool,
	activityUpdater ActivityUpdater,
	lruEntry *LRUConnsEntry) (*ActivityMonitoredConn, error) {

	if inactivityTimeout > 0 {
		err := conn.SetDeadline(time.Now().Add(inactivityTimeout))
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	now := int64(monotime.Now())

	return &ActivityMonitoredConn{
		Conn:                 conn,
		inactivityTimeout:    inactivityTimeout,
		activeOnWrite:        activeOnWrite,
		realStartTime:        time.Now(),
		monotonicStartTime:   now,
		lastReadActivityTime: now,
		activityUpdater:      activityUpdater,
		lruEntry:             lruEntry,
	}, nil
}

// GetStartTime gets the time when the ActivityMonitoredConn was
// initialized. Reported time is UTC.
func (conn *ActivityMonitoredConn) GetStartTime() time.Time {
	return conn.realStartTime.UTC()
}

// GetActiveDuration returns the time elapsed between the initialization
// of the ActivityMonitoredConn and the last Read. Only reads are used
// for this calculation since writes may succeed locally due to buffering.
func (conn *ActivityMonitoredConn) GetActiveDuration() time.Duration {
	return time.Duration(atomic.LoadInt64(&conn.lastReadActivityTime) - conn.monotonicStartTime)
}

// GetLastActivityMonotime returns the arbitrary monotonic time of the last Read.
func (conn *ActivityMonitoredConn) GetLastActivityMonotime() monotime.Time {
	return monotime.Time(atomic.LoadInt64(&conn.lastReadActivityTime))
}

func (conn *ActivityMonitoredConn) Read(buffer []byte) (int, error) {
	n, err := conn.Conn.Read(buffer)
	if err == nil {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, errors.Trace(err)
			}
		}

		readActivityTime := int64(monotime.Now())

		if conn.activityUpdater != nil {
			conn.activityUpdater.UpdateProgress(
				int64(n), 0, readActivityTime-atomic.LoadInt64(&conn.lastReadActivityTime))
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

		atomic.StoreInt64(&conn.lastReadActivityTime, readActivityTime)

	}
	// Note: no context error to preserve error type
	return n, err
}

func (conn *ActivityMonitoredConn) Write(buffer []byte) (int, error) {
	n, err := conn.Conn.Write(buffer)
	if err == nil && conn.activeOnWrite {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, errors.Trace(err)
			}
		}

		if conn.activityUpdater != nil {
			conn.activityUpdater.UpdateProgress(0, int64(n), 0)
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

	}
	// Note: no context error to preserve error type
	return n, err
}

// IsClosed implements the Closer iterface. The return value
// indicates whether the underlying conn has been closed.
func (conn *ActivityMonitoredConn) IsClosed() bool {
	closer, ok := conn.Conn.(Closer)
	if !ok {
		return false
	}
	return closer.IsClosed()
}

// IsBogon checks if the specified IP is a bogon (loopback, private addresses,
// link-local addresses, etc.)
func IsBogon(IP net.IP) bool {
	return filtertransport.FindIPNet(
		filtertransport.DefaultFilteredNetworks, IP)
}

// ParseDNSQuestion parses a DNS message. When the message is a query,
// the first question, a fully-qualified domain name, is returned.
//
// For other valid DNS messages, "" is returned. An error is returned only
// for invalid DNS messages.
//
// Limitations:
// - Only the first Question field is extracted.
// - ParseDNSQuestion only functions for plaintext DNS and cannot
//   extract domains from DNS-over-TLS/HTTPS, etc.
func ParseDNSQuestion(request []byte) (string, error) {
	m := new(dns.Msg)
	err := m.Unpack(request)
	if err != nil {
		return "", errors.Trace(err)
	}
	if len(m.Question) > 0 {
		return m.Question[0].Name, nil
	}
	return "", nil
}
