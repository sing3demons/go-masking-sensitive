package main

import (
	"encoding/json"
	"net/http"

	"github.com/sing3demons/sensitive/mask/masking"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	MobileNo string `json:"mobileNO"`
	NickName string `json:"nickName"`
	User     IUser  `json:"user"`
}
type IUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	MobileNo string `json:"mobileNO"`
}

type Response struct {
	Status string `json:"status"`
	Data   User   `json:"data"`
}

func main() {
	data := User{
		Email:    "sing@dev.com",
		NickName: "sing",
		Password: "123456",
		Name:     "sing",
		MobileNo: "0987654321",
		User: IUser{
			Email: "sing@dev..com",
		},
	}
	response := Response{
		Status: "success",
		Data:   data,
	}

	sensitive := masking.NewMaskSensitive()
	mk := sensitive.MaskSensitiveData(response)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mk)
	})

	http.ListenAndServe(":8080", nil)
}
