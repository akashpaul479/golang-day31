package main

import (
	"jwt/jwt2"
)

func main() {

	// token, err := jwt1.GenerateJwt(1, "akash@gmail.com")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(token)

	jwt2.CrudRestApiWithJWT()
}
