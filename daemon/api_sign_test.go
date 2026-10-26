// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
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

package daemon_test

// Tests for the mediated assertion signing endpoints (daemon/api_sign.go).
//
// Denial paths are exercised through the *real* access checker
// (checkAccess -> requireInterfaceApiAccessImpl against seeded connection
// state, and the polkit mock), mirroring daemon/access_test.go. Happy paths
// exercise the handler with the access wiring asserted by apiBaseSuite.req.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/asserts/signtool"
	"github.com/snapcore/snapd/daemon"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/auth"
)

const signTestInstance = "some-snap" // from security tag snap.some-snap.app

type signAPIsSuite struct {
	apiBaseSuite
}

var _ = Suite(&signAPIsSuite{})

// fakeSignKeyMgr is a minimal signtool.KeypairManager over a name->key map.
type fakeSignKeyMgr struct {
	byName map[string]asserts.PrivateKey
	byID   map[string]asserts.PrivateKey
}

func newFakeSignKeyMgr(c *C, name string, key asserts.PrivateKey) *fakeSignKeyMgr {
	f := &fakeSignKeyMgr{
		byName: make(map[string]asserts.PrivateKey),
		byID:   make(map[string]asserts.PrivateKey),
	}
	if name != "" {
		f.byName[name] = key
		f.byID[key.PublicKey().ID()] = key
	}
	return f
}

func (f *fakeSignKeyMgr) Put(privKey asserts.PrivateKey) error {
	f.byName["key-"+privKey.PublicKey().ID()] = privKey
	f.byID[privKey.PublicKey().ID()] = privKey
	return nil
}

func (f *fakeSignKeyMgr) Get(keyID string) (asserts.PrivateKey, error) {
	k, ok := f.byID[keyID]
	if !ok {
		return nil, errors.New("cannot find key pair")
	}
	return k, nil
}

func (f *fakeSignKeyMgr) Delete(keyID string) error {
	delete(f.byID, keyID)
	return nil
}

func (f *fakeSignKeyMgr) GetByName(name string) (asserts.PrivateKey, error) {
	k, ok := f.byName[name]
	if !ok {
		return nil, errors.New(`cannot find key with name "default"`)
	}
	return k, nil
}

func (f *fakeSignKeyMgr) Export(name string) ([]byte, error) {
	return nil, errors.New("export is not supported")
}

func (f *fakeSignKeyMgr) List() ([]asserts.ExternalKeyInfo, error) {
	var out []asserts.ExternalKeyInfo
	for name, k := range f.byName {
		out = append(out, asserts.ExternalKeyInfo{Name: name, ID: k.PublicKey().ID()})
	}
	return out, nil
}

func (f *fakeSignKeyMgr) DeleteByName(name string) error {
	delete(f.byName, name)
	return nil
}

var _ signtool.KeypairManager = (*fakeSignKeyMgr)(nil)

// modelStatement is a minimal model assertion statement. It signs cleanly
// with a bare keypair manager (no account-key cross-check), mirroring
// asserts/signtool/sign_test.go.
func modelStatement() map[string]any {
	return map[string]any{
		"type":         "model",
		"series":       "16",
		"authority-id": "can0nical",
		"brand-id":     "can0nical",
		"model":        "baz-3000",
		"architecture": "amd64",
		"gadget":       "brand-gadget",
		"kernel":       "baz-linux",
		"store":        "brand-store",
		"timestamp":    "2015-11-25T20:00:00Z",
	}
}

// seedConn seeds an active assertion-sign connection for the test instance.
// Non-empty types adds a plug "assertion-types" allow-list attribute.
func (s *signAPIsSuite) seedConn(c *C, types ...string) {
	st := s.d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	conn := map[string]any{"interface": "assertion-sign"}
	if len(types) > 0 {
		list := make([]any, 0, len(types))
		for _, t := range types {
			list = append(list, t)
		}
		conn["plug-static"] = map[string]any{"assertion-types": list}
	}
	st.Set("conns", map[string]any{
		signTestInstance + ":signer core:assertion-sign": conn,
	})
}

func signUcred(uid uint32) *daemon.Ucrednet {
	return daemon.NewUcrednet("snap.some-snap.app", "", uid, dirs.SnapSocket)
}

func (s *signAPIsSuite) signAccess() daemon.AccessChecker {
	return daemon.InterfaceRootAccess{
		Interfaces: []string{"assertion-sign"},
		Polkit:     daemon.PolkitActionSign,
	}
}

func (s *signAPIsSuite) signReq(c *C, body any) *http.Request {
	b, err := json.Marshal(body)
	c.Assert(err, IsNil)
	req, err := http.NewRequest("POST", "/v2/assertions/sign", bytes.NewReader(b))
	c.Assert(err, IsNil)
	return req
}

// --- access checker: denial + grant paths (real connection state) ----------

func (s *signAPIsSuite) TestSignAssertDeniedWithoutConnection(c *C) {
	s.daemon(c)
	// no connection seeded at all

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	ucred := signUcred(1000)
	c.Check(s.signAccess().CheckAccess(s.d, req, ucred, nil, newAuthzRecorder()),
		DeepEquals, errForbidden,
		Commentf("a caller without a connected assertion-sign plug must be denied"))
}

func (s *signAPIsSuite) TestSignAssertDeniedWithoutConnectionForOtherSnap(c *C) {
	s.daemon(c)
	// connection exists, but for a different snap
	st := s.d.Overlord().State()
	st.Lock()
	st.Set("conns", map[string]any{
		"other-snap:signer core:assertion-sign": map[string]any{"interface": "assertion-sign"},
	})
	st.Unlock()

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	ucred := signUcred(1000)
	c.Check(s.signAccess().CheckAccess(s.d, req, ucred, nil, newAuthzRecorder()),
		DeepEquals, errForbidden,
		Commentf("another snap's connection must not grant access (tag isolation)"))
}

func (s *signAPIsSuite) TestSignAssertDeniedByPolkit(c *C) {
	s.daemon(c)
	s.seedConn(c)

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	ucred := signUcred(1000)

	restore := daemon.MockCheckPolkitAction(func(r *http.Request, ucred *daemon.Ucrednet, action string) *daemon.APIError {
		c.Check(action, Equals, daemon.PolkitActionSign)
		return errUnauthorized
	})
	defer restore()
	c.Check(s.signAccess().CheckAccess(s.d, req, ucred, nil, newAuthzRecorder()),
		DeepEquals, errUnauthorized,
		Commentf("polkit denial must be unauthorized for a non-root caller"))
}

func (s *signAPIsSuite) TestSignAssertGrantedWhenConnectedAndPolkitAllows(c *C) {
	s.daemon(c)
	s.seedConn(c)

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	ucred := signUcred(1000)

	restore := daemon.MockCheckPolkitAction(func(r *http.Request, ucred *daemon.Ucrednet, action string) *daemon.APIError {
		c.Check(action, Equals, daemon.PolkitActionSign)
		return nil
	})
	defer restore()
	c.Check(s.signAccess().CheckAccess(s.d, req, ucred, nil, newAuthzRecorder()), IsNil,
		Commentf("connected plug + polkit grant must be allowed"))
}

func (s *signAPIsSuite) TestSignAssertRootGrantedWithoutPolkit(c *C) {
	s.daemon(c)
	s.seedConn(c)

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	ucred := signUcred(0)

	// polkit must not be consulted for root
	restore := daemon.MockCheckPolkitAction(func(r *http.Request, ucred *daemon.Ucrednet, action string) *daemon.APIError {
		c.Fatal("polkit must not be consulted for root")
		return errForbidden
	})
	defer restore()
	c.Check(s.signAccess().CheckAccess(s.d, req, ucred, nil, newAuthzRecorder()), IsNil)
}

func (s *signAPIsSuite) TestSignAssertLoggedInUserStillNeedsPolkit(c *C) {
	// The sign endpoint is root-level access: a macaroon-logged-in user is
	// NOT auto-granted (that shortcut only exists at the "authenticated"
	// access level). A login alone must never be enough to sign; explicit
	// polkit consent is required.
	s.daemon(c)
	s.seedConn(c)

	req := httptest.NewRequest("POST", "/v2/assertions/sign", nil)
	st := s.d.Overlord().State()
	st.Lock()
	u, err := auth.NewUser(st, auth.NewUserParams{
		Username:   "username",
		Email:      "email@test.com",
		Macaroon:   "macaroon",
		Discharges: []string{"discharge"},
	})
	st.Unlock()
	c.Assert(err, IsNil)

	called := 0
	restore := daemon.MockCheckPolkitAction(func(r *http.Request, ucred *daemon.Ucrednet, action string) *daemon.APIError {
		called++
		return nil // user consents
	})
	defer restore()
	c.Check(s.signAccess().CheckAccess(s.d, req, signUcred(1000), u, newAuthzRecorder()), IsNil)
	c.Check(called, Equals, 1, Commentf("polkit must be consulted for logged-in users"))
}

// --- handler behavior (access wiring asserted by apiBaseSuite.req) ---------

func (s *signAPIsSuite) TestSignAssertHappy(c *C) {
	s.daemon(c)
	s.seedConn(c)
	s.expectWriteAccess(s.signAccess())

	key, _ := assertstest.GenerateKey(752)
	s.AddCleanup(daemon.MockSignKeypairManager(func() (signtool.KeypairManager, error) {
		return newFakeSignKeyMgr(c, "default", key), nil
	}))

	req := s.signReq(c, map[string]any{
		"key":       "default",
		"statement": modelStatement(),
	})
	daemon.AddUcrednetToRequest(req, signUcred(0))

	rsp := s.syncReq(c, req, nil, false)
	text, ok := rsp.Result.(string)
	c.Assert(ok, Equals, true, Commentf("result must be the signed assertion text: %#v", rsp.Result))
	// Decode round-trips and proves the output is a well-formed assertion
	// signed by our daemon-held key (see SignKeyID check below).
	a, err := asserts.Decode([]byte(text))
	c.Assert(err, IsNil)
	c.Check(a.Type(), Equals, asserts.ModelType)
	c.Check(a.Headers()["model"], Equals, "baz-3000")
	c.Check(a.Revision(), Equals, 0)
	c.Check(a.SignKeyID(), Equals, key.PublicKey().ID())
}

func (s *signAPIsSuite) TestSignAssertTypeNotAllowed(c *C) {
	s.daemon(c)
	s.seedConn(c, "account") // this connection may only sign "account"
	s.expectWriteAccess(s.signAccess())

	key, _ := assertstest.GenerateKey(752)
	s.AddCleanup(daemon.MockSignKeypairManager(func() (signtool.KeypairManager, error) {
		return newFakeSignKeyMgr(c, "default", key), nil
	}))

	req := s.signReq(c, map[string]any{
		"key":       "default",
		"statement": modelStatement(), // "model" is not in the allow-list
	})
	daemon.AddUcrednetToRequest(req, signUcred(0))

	rspe := s.errorReq(c, req, nil, false)
	c.Check(rspe.Status, Equals, 403)
	c.Check(rspe.Message, Matches, `assertion type "model" is not allowed for this connection.*`)
}

func (s *signAPIsSuite) TestSignAssertMissingKey(c *C) {
	s.daemon(c)
	s.seedConn(c)
	s.expectWriteAccess(s.signAccess())

	s.AddCleanup(daemon.MockSignKeypairManager(func() (signtool.KeypairManager, error) {
		return newFakeSignKeyMgr(c, "", nil), nil // no keys at all
	}))

	req := s.signReq(c, map[string]any{
		"key":       "default",
		"statement": modelStatement(),
	})
	daemon.AddUcrednetToRequest(req, signUcred(0))

	rspe := s.errorReq(c, req, nil, false)
	c.Check(rspe.Status, Equals, 400)
	c.Check(rspe.Message, Matches, `cannot use "default" key.*`)
}

func (s *signAPIsSuite) TestSignAssertMissingStatement(c *C) {
	s.daemon(c)
	s.seedConn(c)
	s.expectWriteAccess(s.signAccess())

	req := s.signReq(c, map[string]any{"key": "default"})
	daemon.AddUcrednetToRequest(req, signUcred(0))

	rspe := s.errorReq(c, req, nil, false)
	c.Check(rspe.Status, Equals, 400)
	c.Check(rspe.Message, Matches, `missing "statement"`)
}

func (s *signAPIsSuite) TestSignAssertNoConnectionPolicyBug(c *C) {
	s.daemon(c)
	// no connection: the access checker would reject this request in the
	// real pipeline; at the handler level it must not sign anything.
	s.expectWriteAccess(s.signAccess())

	key, _ := assertstest.GenerateKey(752)
	s.AddCleanup(daemon.MockSignKeypairManager(func() (signtool.KeypairManager, error) {
		return newFakeSignKeyMgr(c, "default", key), nil
	}))

	req := s.signReq(c, map[string]any{
		"key":       "default",
		"statement": modelStatement(),
	})
	daemon.AddUcrednetToRequest(req, signUcred(0))

	rspe := s.errorReq(c, req, nil, false)
	c.Check(rspe.Status, Equals, 500)
	c.Check(rspe.Message, Matches, `no active assertion-sign connection for `+`"`+signTestInstance+`"`)
}

func (s *signAPIsSuite) TestListKeysAccess(c *C) {
	s.daemon(c)
	cmd, _ := handlerCommand(c, s.d, httptest.NewRequest("GET", "/v2/keys", nil))
	c.Check(cmd.ReadAccess, DeepEquals, daemon.InterfaceOpenAccess{
		Interfaces: []string{"assertion-sign"},
	})
}

func (s *signAPIsSuite) TestListKeys(c *C) {
	s.daemon(c)
	s.expectReadAccess(daemon.InterfaceOpenAccess{
		Interfaces: []string{"assertion-sign"},
	})

	key, _ := assertstest.GenerateKey(752)
	s.AddCleanup(daemon.MockSignKeypairManager(func() (signtool.KeypairManager, error) {
		return newFakeSignKeyMgr(c, "default", key), nil
	}))

	req := httptest.NewRequest("GET", "/v2/keys", nil)
	daemon.AddUcrednetToRequest(req, signUcred(0))
	rsp := s.syncReq(c, req, nil, false)
	c.Assert(rsp.Result, NotNil)
}
