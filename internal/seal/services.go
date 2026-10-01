package seal

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

type Services struct {
	HTTP       string `json:"http"`
	Management string `json:"management"`
	TCP        string `json:"tcp,omitempty"`
	UDP        string `json:"udp,omitempty"`
	DNS        string `json:"dns,omitempty"`
	cancel     context.CancelFunc
	closers    []func()
	mu         sync.Mutex
	done       chan error
}

func (s *Services) Close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, close := range s.closers {
		close()
	}
	s.closers = nil
}
func (s *Services) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-s.done:
		return err
	}
}

func (s *Services) http(ctx context.Context, address string, handler http.Handler) (string, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return "", err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	s.closers = append(s.closers, func() { _ = server.Close() })
	go func() {
		err := server.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			select {
			case s.done <- err:
			default:
			}
		}
	}()
	return "http://" + l.Addr().String(), nil
}

type ReceiverOptions struct{ HTTP, Management, TCP, UDP, DNS, Zone, Token string }

func StartReceiver(parent context.Context, opts ReceiverOptions) (*Services, error) {
	if len(opts.Token) < 16 || !validZone(opts.Zone) {
		return nil, errors.New("receiver requires a token of at least 16 characters and a valid zone")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Services{cancel: cancel, done: make(chan error, 8)}
	o := NewObserver(opts.Zone)
	var err error
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	s.HTTP, err = s.http(ctx, opts.HTTP, o)
	if err != nil {
		return nil, err
	}
	s.Management, err = s.http(ctx, opts.Management, o.Management(opts.Token))
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", opts.TCP)
	if err != nil {
		return nil, err
	}
	s.TCP = l.Addr().String()
	s.closers = append(s.closers, func() { _ = l.Close() })
	go func() {
		if e := o.ServeTCP(ctx, l); e != nil {
			select {
			case s.done <- e:
			default:
			}
		}
	}()
	for _, entry := range []struct {
		address string
		dns     bool
	}{{opts.UDP, false}, {opts.DNS, true}} {
		var c net.PacketConn
		c, err = net.ListenPacket("udp", entry.address)
		if err != nil {
			return nil, err
		}
		if entry.dns {
			s.DNS = c.LocalAddr().String()
		} else {
			s.UDP = c.LocalAddr().String()
		}
		s.closers = append(s.closers, func() { _ = c.Close() })
		go func(dns bool) {
			if e := o.ServeUDP(ctx, c, dns); e != nil {
				select {
				case s.done <- e:
				default:
				}
			}
		}(entry.dns)
	}
	return s, nil
}

func StartFixture(parent context.Context, fixture *Fixture, listen, management, token string) (*Services, error) {
	if len(token) < 16 {
		return nil, errors.New("fixture requires a management token of at least 16 characters")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Services{cancel: cancel, done: make(chan error, 8)}
	var err error
	s.HTTP, err = s.http(ctx, listen, fixture)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.Management, err = s.http(ctx, management, fixture.Observer.Management(token))
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
