package encryption

import (
	"errors"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	saltLength  = 24
	encryptCost = 12
	rehashDays  = 14
	dateFormat  = "20060102T150405"
	runes       = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// PasswordHash struct
type PasswordHash struct {
	SaltLength  int
	RehashDays  int
	EncryptCost int
}

// NewPasswordHash returns an instance of PasswordHash
func NewPasswordHash() *PasswordHash {
	return &PasswordHash{
		SaltLength:  saltLength,
		RehashDays:  rehashDays,
		EncryptCost: encryptCost,
	}
}

// SetSaltLength sets the length of the salt
func (p *PasswordHash) SetSaltLength(value int) *PasswordHash {
	p.SaltLength = value
	return p
}

// SetRehashDays sets the number of days to the next rehash date
func (p *PasswordHash) SetRehashDays(value int) *PasswordHash {
	p.RehashDays = value
	return p
}

// SetEncryptCost sets the number of hash iterations
func (p *PasswordHash) SetEncryptCost(value int) *PasswordHash {
	p.EncryptCost = value
	return p
}

// Make creates a new hash/salt combo from the input
func (p PasswordHash) Make(rawPassword string) (string, string, error) {
	salt := p.generateSalt(p.SaltLength)
	saltedPass := p.combine(salt, rawPassword)
	password, err := p.hashPassword(saltedPass)

	if err != nil {
		return "", "", err
	}

	return p.addRehashDate(password), salt, nil
}

// Match checks whether or not the correct password has been provided
func (p PasswordHash) Match(rawPassword string, hashedPassword string, salt string) (bool, error) {
	saltedGuess := p.combine(salt, rawPassword)
	_, pass, err := p.getPasswordAndDate(hashedPassword)
	if err != nil {
		return false, err
	}

	return bcrypt.CompareHashAndPassword([]byte(pass), []byte(saltedGuess)) == nil, nil
}

// RehashNeeded checks if it is time to rehash the password
func (p PasswordHash) RehashNeeded(hashedPassword string) (bool, error) {
	date, _, err := p.getPasswordAndDate(hashedPassword)
	if err != nil {
		return false, err
	}

	rehashTime, err := time.Parse(dateFormat, date)
	if err != nil {
		return false, err
	}

	return time.Now().Before(rehashTime), nil
}

func (p PasswordHash) hashPassword(saltedPassword string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), p.EncryptCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func (PasswordHash) combine(salt string, rawPassword string) string {
	pieces := []string{salt, rawPassword}
	return strings.Join(pieces, "")
}

func (PasswordHash) generateSalt(length int) string {
	rand.Seed(time.Now().UnixNano())
	runeString := []rune(runes)

	str := make([]rune, length)
	for i := range str {
		str[i] = runeString[rand.Intn(len(runeString))]
	}
	return string(str)
}

func (p PasswordHash) addRehashDate(hashedPassword string) string {
	return strings.Join([]string{p.getDateString(), hashedPassword}, ".")
}

func (p PasswordHash) getDateString() string {
	addedTime := time.Hour * 24 * time.Duration(p.RehashDays)
	return time.Now().Add(addedTime).Format(dateFormat)
}

func (PasswordHash) getPasswordAndDate(hashedPassword string) (string, string, error) {
	splitted := strings.SplitN(hashedPassword, ".", 2)
	if len(splitted) != 2 {
		return "", "", errors.New("Invalid hashed password format")
	}

	date := splitted[0]
	password := splitted[1]

	return date, password, nil
}
