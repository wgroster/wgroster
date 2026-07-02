package store

import (
	"bytes"
	"testing"
)

func TestUserProfileRoundTrip(t *testing.T) {
	st := newTestStore(t)

	// Unknown user: no profile, no photo.
	if _, _, _, found, err := st.UserProfileMeta("ghost"); err != nil || found {
		t.Fatalf("UserProfileMeta(ghost) = found %v, err %v", found, err)
	}
	if _, _, ok, err := st.UserPhoto("ghost"); err != nil || ok {
		t.Fatalf("UserPhoto(ghost) = ok %v, err %v", ok, err)
	}

	// Name only, no photo.
	if err := st.UpsertUserProfile("alice", "Alice Martin", nil, ""); err != nil {
		t.Fatal(err)
	}
	name, hasPhoto, fetchedAt, found, err := st.UserProfileMeta("alice")
	if err != nil || !found {
		t.Fatalf("meta: found %v err %v", found, err)
	}
	if name != "Alice Martin" || hasPhoto {
		t.Errorf("meta = %q hasPhoto=%v, want name set and no photo", name, hasPhoto)
	}
	if fetchedAt.IsZero() {
		t.Error("expected a non-zero fetched_at")
	}

	// Add a photo via upsert; it should replace the row and report a photo.
	photo := []byte{0x89, 'P', 'N', 'G', 1, 2, 3}
	if err := st.UpsertUserProfile("alice", "Alice Martin", photo, "image/png"); err != nil {
		t.Fatal(err)
	}
	_, hasPhoto, _, _, _ = st.UserProfileMeta("alice")
	if !hasPhoto {
		t.Error("expected hasPhoto after upsert with a photo")
	}
	got, ptype, ok, err := st.UserPhoto("alice")
	if err != nil || !ok {
		t.Fatalf("UserPhoto: ok %v err %v", ok, err)
	}
	if !bytes.Equal(got, photo) || ptype != "image/png" {
		t.Errorf("UserPhoto = %v %q, want %v image/png", got, ptype, photo)
	}

	// Clearing the photo (nil) makes UserPhoto report absent again.
	if err := st.UpsertUserProfile("alice", "Alice Martin", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.UserPhoto("alice"); ok {
		t.Error("expected no photo after clearing it")
	}
}
