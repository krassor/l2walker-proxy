package utils

import (
	"encoding/json"
	"net/http"
	"regexp"
)

func Message(statusOK bool, message interface{}) map[string]interface{} {
	if statusOK {
		return map[string]interface{}{"status": "OK", "message": message}
	}
	return map[string]interface{}{"status": "error", "message": message}

}

func Respond(w http.ResponseWriter, data map[string]interface{}) error {
	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		return err
	}
	return nil
}

func Json(w http.ResponseWriter, httpCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	err := json.NewEncoder(w).Encode(&data)
	if err != nil {
		return err
	}
	return nil
}

func Text(w http.ResponseWriter, httpCode int, message string) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(httpCode)
	_, err := w.Write([]byte(message))
	if err != nil {
		return err
	}
	return nil
}

func Err(w http.ResponseWriter, httpCode int, err error) error {

	w.Header().Set("Content-Type", "application/json")
	//need more error status
	w.WriteHeader(httpCode)
	res := Message(false, err.Error())
	returnErr := json.NewEncoder(w).Encode(res)
	if returnErr != nil {
		return returnErr
	}
	return nil
}

func IsEmailValid(e string) bool {
	emailRegex := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return emailRegex.MatchString(e)
}
