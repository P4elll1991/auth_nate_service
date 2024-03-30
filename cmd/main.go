package main

import (
	"auth/internal/handler"
	"auth/internal/service"
	"fmt"
)

func main() {
	fmt.Println("START")

	handler.New(service.NewJWTService()).Run()
}
