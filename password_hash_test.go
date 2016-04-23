package encryption

import "testing"

type testCasePasswordMatch struct {
	SaltLength    int
	EncryptCost   int
	Password      string
	PasswordMatch string
	Actualt       bool
}

func TestPasswordMatch(t *testing.T) {
	cases := []testCasePasswordMatch{
		{
			Password:      "mySecretPassword1#3",
			PasswordMatch: "mySecretPassword1#3",
			Actualt:       true,
		},
		{
			Password:      "mySecretPassword1#3",
			PasswordMatch: "mySecretPa33word1#3",
			Actualt:       false,
		},
		{
			EncryptCost:   4,
			SaltLength:    6,
			Password:      "t3st!X?123#3",
			PasswordMatch: "t3st!X?123#3",
			Actualt:       true,
		},
		{
			EncryptCost:   4,
			SaltLength:    6,
			Password:      "asd987Wt",
			PasswordMatch: "asd987wt",
			Actualt:       false,
		},
	}

	p := NewPasswordHash()
	for _, c := range cases {
		if c.SaltLength != 0 {
			p.SaltLength = c.SaltLength
		}
		if c.EncryptCost != 0 {
			p.EncryptCost = c.EncryptCost
		}

		pass, salt, err := p.Make(c.Password)
		if err != nil {
			t.Errorf("Error: %s", err)
		}

		if len(salt) != p.SaltLength {
			t.Errorf("Salt length is %v expected %v", len(salt), p.SaltLength)
		}

		result, err := p.Match(c.PasswordMatch, pass, salt)
		if err != nil {
			t.Errorf("Error: %s", err)
		}

		if result != c.Actualt {
			t.Errorf("Expected: %t Got: %t", c.Actualt, result)
		}
	}
}
