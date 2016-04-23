package encryption

import "testing"

type aesTestCase struct {
	Actual string
}

func TestAes(t *testing.T) {
	cases := []aesTestCase{
		{
			Actual: "someValue",
		},
		{
			Actual: "String That will Be 3ncryPted",
		},
		{
			Actual: "qwertyuiopåasdfghjklöäzxcvbnm1234567890!#€%&/()=",
		},
		{
			Actual: "QWERTYUIOPÅASDFGHJKLÖÄZXCVBNMqwertyuiopåäölkjhgfdsaxcvbnm1234567890=)(/&%€#\"!)©@£$∞§|[]≈±",
		},
	}

	a1 := NewAesWithKey()
	runAesTest(a1, cases, t)

	a2 := NewAes("LbF42s8rFNxJ@c2So26Aw!3q?#v?CXi3")
	runAesTest(a2, cases, t)
}

func runAesTest(a *Aes, cases []aesTestCase, t *testing.T) {
	for _, c := range cases {
		value, err := a.Encrypt(c.Actual)
		if err != nil {
			t.Errorf("Error %s", err)
		}

		result, err := a.Decrypt(value)
		if err != nil {
			t.Errorf("Error %s", err)
		}

		if result != c.Actual {
			t.Errorf("Expected: %s Got: %s", c.Actual, result)
		}
	}
}
