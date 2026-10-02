package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(hash), err

}

func main() {
	pass, _ := hashPassword("224217007Kk@")
	pass1, _ := hashPassword("224217007Kk@")
	fmt.Println(pass)
	fmt.Println(pass1)
}
