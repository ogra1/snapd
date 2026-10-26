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

package builtin

import (
	"fmt"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/snap"
)

const assertionSignSummary = `allows signing assertions mediated by snapd`

const assertionSignBaseDeclarationPlugs = `
  assertion-sign:
    allow-installation: false
    deny-auto-connection: true
`

const assertionSignBaseDeclarationSlots = `
  assertion-sign:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

// The interface grants no new AppArmor rules: every restricted snap already
// has /run/snapd-snap.socket (base AppArmor template) and the daemon gates the
// sign endpoint by the connection + peer credentials (ucred security tag ->
// snap instance name), see requireInterfaceApiAccessImpl in daemon/access.go.

type assertionSignInterface struct {
	commonInterface
}

// BeforePreparePlug validates plug attributes at connection time so an invalid
// allow-list fails fast (at connect) rather than at signing time.
func (i *assertionSignInterface) BeforePreparePlug(plug *snap.PlugInfo) error {
	types, ok := plug.Attrs["assertion-types"]
	if !ok {
		// Open question O4: default when the attribute is omitted. This
		// skeleton implements "allow-all"; flip to deny-all per review.
		return nil
	}
	for _, t := range types.([]any) {
		s, ok := t.(string)
		if !ok || asserts.Type(s) == nil {
			return fmt.Errorf("unknown assertion type %v in plug attribute \"assertion-types\"", t)
		}
	}
	return nil
}

func init() {
	registerIface(&assertionSignInterface{commonInterface{
		name:                 "assertion-sign",
		summary:              assertionSignSummary,
		implicitOnCore:       false,
		implicitOnClassic:    false,
		baseDeclarationPlugs: assertionSignBaseDeclarationPlugs,
		baseDeclarationSlots: assertionSignBaseDeclarationSlots,
	}})
}
