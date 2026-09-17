package relay

import (
	"bytes"
	"testing"
	"time"

	"github.com/mouizahmed/sshstate/internal/protocol"
)

func digestOf(t *testing.T, env *protocol.Envelope) []byte {
	t.Helper()
	d, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (h *harness) importing(history string, items ...protocol.ImportRecord) []protocol.ImportOutcome {
	h.t.Helper()
	res, err := h.store.ImportRecords(h.vaultID, &protocol.ImportRequest{History: history, Records: items}, stamp)
	if err != nil {
		h.t.Fatal(err)
	}
	return res.Outcomes
}

func item(env *protocol.Envelope, ancestors ...[]byte) protocol.ImportRecord {
	out := protocol.ImportRecord{Envelope: *env}
	for _, a := range ancestors {
		out.Ancestors = append(out.Ancestors, a)
	}
	return out
}

func wantOutcome(t *testing.T, got protocol.ImportOutcome, want string) {
	t.Helper()
	if got.Outcome != want {
		t.Fatalf("record %s: outcome %s, want %s", got.RecordID, got.Outcome, want)
	}
}

func TestImportDecidesByAncestry(t *testing.T) {
	h := newHarness(t)
	x := protocol.MustNewID()
	rev1 := h.envelope(h.first, x, 1, nil, false, "one")
	h.mustPut(rev1)
	rev2 := h.envelope(h.first, x, 2, digestOf(t, rev1), false, "two")
	h.mustPut(rev2)

	rev3 := h.envelope(h.first, x, 3, digestOf(t, rev2), false, "three")
	out := h.importing("", item(rev3))[0]
	wantOutcome(t, out, protocol.ImportImported)
	if out.Seq == 0 {
		t.Fatal("an imported record got no seq")
	}
	wantOutcome(t, h.importing("", item(rev3))[0], protocol.ImportCurrent)
	wantOutcome(t, h.importing("", item(rev2))[0], protocol.ImportBehind)

	other3 := h.envelope(h.first, x, 3, digestOf(t, rev2), false, "other three")
	diverged := h.importing("", item(other3))[0]
	wantOutcome(t, diverged, protocol.ImportDiverged)
	if diverged.Head == nil || !bytes.Equal(digestOf(t, diverged.Head), digestOf(t, rev3)) {
		t.Fatal("a diverged outcome did not carry the relay's head")
	}

	rev4 := h.envelope(h.first, x, 4, digestOf(t, rev3), false, "four")
	rev5 := h.envelope(h.first, x, 5, digestOf(t, rev4), false, "five")
	wantOutcome(t, h.importing("", item(rev5, digestOf(t, rev3)))[0], protocol.ImportImported)
	head, err := h.store.Head(h.vaultID, x)
	if err != nil || head.Context.Rev != 5 {
		t.Fatalf("the head did not move forward to rev 5: %v %v", head, err)
	}

	unrelated5 := h.envelope(h.first, x, 5, digestOf(t, rev4), false, "unrelated")
	wantOutcome(t, h.importing("", item(unrelated5, digestOf(t, rev2)))[0], protocol.ImportDiverged)

	y := protocol.MustNewID()
	lone := h.envelope(h.first, y, 4, bytes.Repeat([]byte{7}, 32), false, "lone")
	wantOutcome(t, h.importing("", item(lone))[0], protocol.ImportImported)

	after := h.envelope(h.first, x, 6, digestOf(t, rev5), false, "six")
	h.mustPut(after)
}

func TestImportRestartsTheHistoryOnlyForACallerStillOnIt(t *testing.T) {
	h := newHarness(t)
	start, origin, err := h.store.History()
	if err != nil || start == "" || origin != protocol.HistoryCreated {
		t.Fatalf("a new vault has history (%q, %q, %v)", start, origin, err)
	}
	x := protocol.MustNewID()
	first := h.envelope(h.first, x, 1, nil, false, "one")
	h.importing("someone else's", item(first))
	if got, _, _ := h.store.History(); got != start {
		t.Fatal("an import from a caller on another history restarted it")
	}

	second := h.envelope(h.first, x, 2, digestOf(t, first), false, "two")
	h.importing(start, item(second))
	restarted, origin, _ := h.store.History()
	if restarted == start || origin != protocol.HistoryRestarted {
		t.Fatalf("an import from a caller still on the history did not restart it (%q, %q)", restarted, origin)
	}

	h.importing(restarted, item(second))
	if got, _, _ := h.store.History(); got != restarted {
		t.Fatal("an import that changed nothing restarted the history")
	}
}

func TestImportAcceptsWritersRevokedSinceButPutRecordDoesNot(t *testing.T) {
	h := newHarness(t)
	later := newDevice(t)
	if _, err := h.store.AppendMembership(h.vaultID, h.enrolment(later, bytes.Repeat([]byte{1}, 32))); err != nil {
		t.Fatal(err)
	}
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := chain.Revoke(signerFor(h.first), later.id, h.tick())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AppendMembership(h.vaultID, revoke); err != nil {
		t.Fatal(err)
	}

	written := h.envelope(later, protocol.MustNewID(), 1, nil, false, "before revocation")
	_, err = h.put(written)
	mustCode(t, err, protocol.CodeDeviceRevoked)
	wantOutcome(t, h.importing("", item(written))[0], protocol.ImportImported)

	stranger := h.envelope(newDevice(t), protocol.MustNewID(), 1, nil, false, "stranger")
	_, err = h.store.ImportRecords(h.vaultID, &protocol.ImportRequest{Records: []protocol.ImportRecord{item(stranger)}}, stamp)
	mustCode(t, err, protocol.CodeDeviceUnknown)

	forged := h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "forged")
	forged.Ciphertext = []byte("changed after signing")
	_, err = h.store.ImportRecords(h.vaultID, &protocol.ImportRequest{Records: []protocol.ImportRecord{item(forged)}}, stamp)
	mustCode(t, err, protocol.CodeSignatureInvalid)

	wrongEpoch := h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "epoch")
	wrongEpoch.Context.KeyEpoch = 2
	_, err = h.store.ImportRecords(h.vaultID, &protocol.ImportRequest{Records: []protocol.ImportRecord{item(wrongEpoch)}}, stamp)
	mustCode(t, err, protocol.CodeEpochMismatch)

	bad := h.envelope(h.first, protocol.MustNewID(), 1, nil, false, "rolled back")
	_, err = h.store.ImportRecords(h.vaultID, &protocol.ImportRequest{Records: []protocol.ImportRecord{item(bad), item(stranger)}}, stamp)
	if err == nil {
		t.Fatal("a batch with an unauthorized record was accepted")
	}
	if head, _ := h.store.Head(h.vaultID, bad.Context.RecordID); head != nil {
		t.Fatal("a refused batch left part of itself behind")
	}
}

func TestASeededBootstrapKeepsTheWholeChain(t *testing.T) {
	store := emptyStore(t)
	if err := store.SetBootstrapSecret(secret(1)); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	chain, err := h.store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	second := newDevice(t)
	enrol, err := chain.Enroll(signerFor(h.first), second.keys(), bytes.Repeat([]byte{2}, 32), now)
	if err != nil {
		t.Fatal(err)
	}
	chain, err = chain.Append(enrol)
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := chain.Revoke(signerFor(h.first), second.id, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	events := append(chain.Events(), revoke)

	gapped := []protocol.SignedMembershipEvent{events[0], events[2]}
	mustCode(t, store.BootstrapHistory(secret(1), h.genesis, gapped, true), protocol.CodeInvalidRequest)
	if spent, err := store.BootstrapConsumed(); err != nil || spent {
		t.Fatalf("a refused seed spent the secret (%v, %v)", spent, err)
	}

	if err := store.BootstrapHistory(secret(1), h.genesis, events, true); err != nil {
		t.Fatal(err)
	}
	seeded, err := store.Chain(h.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if seeded.Len() != 3 {
		t.Fatalf("the seeded relay holds %d membership events, want 3", seeded.Len())
	}
	if d, ok := seeded.Device(second.id); !ok || !d.Revoked {
		t.Fatal("the seeded relay lost the revocation")
	}
	if _, origin, _ := store.History(); origin != protocol.HistorySeeded {
		t.Fatalf("a seeded relay reports origin %q", origin)
	}
	if _, err := store.AppendMembership(h.vaultID, revoke); err == nil {
		t.Fatal("the seeded chain accepted its own last event again")
	}
}

func TestAncestryIsRecordedForWritesMadeBeforeTheUpgrade(t *testing.T) {
	h := newHarness(t)
	x := protocol.MustNewID()
	rev1 := h.envelope(h.first, x, 1, nil, false, "one")
	h.mustPut(rev1)
	rev2 := h.envelope(h.first, x, 2, digestOf(t, rev1), false, "two")
	h.mustPut(rev2)
	if _, err := h.store.db.Exec(`DELETE FROM record_ancestor`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`DELETE FROM meta WHERE key = ?`, metaAncestorsRecorded); err != nil {
		t.Fatal(err)
	}
	path := h.store.Path()
	h.store.Close()
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	h.store = reopened
	wantOutcome(t, h.importing("", item(rev1))[0], protocol.ImportBehind)
}
