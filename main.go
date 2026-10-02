package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(hash), err

}

func checkPassword(hash, plain string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		return false
	}
	return true

}

type User struct {
	ID           int    `db:"id" json:"id"`
	Email        string `db:"email" json:"email"`
	PasswordHash string `db:"password_hash" json:"-"`
}

func main() {
	pass, _ := hashPassword("224217007Kk@")
	pass1, _ := hashPassword("224217007Kk@")
	fmt.Println(pass)
	fmt.Println(pass1)

	
}
