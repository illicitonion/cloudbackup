package crypto

import (
	"reflect"
	"testing"
)

func TestAuthThenEnc(t *testing.T) {
	got := ReadKeys([]byte(`-----BEGIN Encryption-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END Encryption-----
-----BEGIN Authentication-----
//////////////////////////////////////////8=
-----END Authentication-----`))
	if want := map[string][]byte{"Encryption": allZeros, "Authentication": allOnes}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestEncThenAuth(t *testing.T) {
	got := ReadKeys([]byte(`-----BEGIN Authentication-----
//////////////////////////////////////////8=
-----END Authentication-----
-----BEGIN Encryption-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END Encryption-----`))
	if want := map[string][]byte{"Encryption": allZeros, "Authentication": allOnes}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestOnlyEnc(t *testing.T) {
	got := ReadKeys([]byte(`-----BEGIN Encryption-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END Encryption-----`))
	if want := map[string][]byte{"Encryption": allZeros}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestOnlyAuth(t *testing.T) {
	got := ReadKeys([]byte(`-----BEGIN Authentication-----
//////////////////////////////////////////8=
-----END Authentication-----`))
	if want := map[string][]byte{"Authentication": allOnes}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestEmpty(t *testing.T) {
	got := ReadKeys([]byte{})
	if want := map[string][]byte{}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestSomeButNotOurs(t *testing.T) {
	got := ReadKeys([]byte(`-----BEGIN Meep-----
//////////////////////////////////////////8=
-----END Meep-----`))
	if want := map[string][]byte{"Meep": allOnes}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}

func TestGibberish(t *testing.T) {
	got := ReadKeys([]byte(`oh no!`))
	if want := map[string][]byte{}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}
