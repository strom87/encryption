# Encryption for go

A password encryption that has rehash functionality for passwords over a certain date and AES encryption for messages and other texts.

### Get package
```sh
$ go get github.com/strom87/encryption
```

### Password hash basic usage
```go
userInputPassword := "secretPassword"

p := encryption.NewPasswordHash()

hashedPassword, salt, err := p.Make(userInputPassword)
if err != nil {
    panic(err)
}
// Save hased password and salt to database

ok, err := p.Match(userInputPassword, hashedPassword, salt)
if err != nil {
    panic(err)
}

if ok {
    // Password is correct
    if p.RehashNeeded(hashedPassword) {
        newHashedPassword, salt, _ := p.Make(userInputPassword)
        // Update hased password and salt in database
    }
} else {
    // Passwords is not the same
}
```

### Default values for password hash
**EncryptCost** is set to **12** as default, this is how many times the password hash should be iterated.   
**SaltLength** is set to **24** as default, this is the length of the generated salt.   
**RehashDays** is set to **14** as default, this is how many days it should be between password rehashes.

### Changing default values
```go
p := encryption.NewPasswordHash()
p.EncryptCost = 10
p.SaltLength = 10
p.RehashDays = 4
```

### Changing default values with chaining
```go
p := encryption.NewPasswordHash()
.SetEncryptCost(16)
.SetSaltLength(20)
.SetRehashDays(7)
```

# AES advanced encryption standard
The basic NewAesWithKey has a default key set for the encryption
```go
a := encryption.NewAesWithKey()

encryptedText, err := a.Encrypt("Text to be encrypted")

decryptedText, err := a.Decrypt(encryptedText)
```

### Set your own key
The recommendation is to set your own key to be used for the cryptation.   
The key needs to be a **32** characters long string.

```go
key := "LbF42s8rFNxJ@c2So26Aw!3q?#v?CXi3"

a := NewAes(key)
```