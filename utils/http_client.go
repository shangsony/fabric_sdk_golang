package utils

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	//"strings"
)

/*
  Issue GET request to BlockChain resource
    url is the GET request.
	respStatus is the HTTP response status code and message
	respBody is the HHTP response body
*/
func HttpClientGET(url string) (string, error) {

	log.Println("GetChainInfo ... :", url)
	response, err := http.Get(url)
	if err != nil {
		log.Println(err)
		return err.Error(), err
	} else {
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Println(err)
			return err.Error(), err
		}
		return string(contents), nil
	}
}

/*
  Issue POST request to BlockChain resource.
    url is the target resource.
	payLoad is the REST API payload
	respStatus is the HTTP response status code and message
	respBody is the HHTP response body
*/
func HttpClientGETPOST(url string, payLoad []byte) (string, error) {

	//fmt.Println(">>>>> From postchain >>> ", url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payLoad))
	//req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	var errCount int
	if err != nil {
		log.Println("Error", url, err)
		errCount++
		return err.Error(), err
	}
	errCount = 0
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error")
		return err.Error(), err
	}

	return string(body), nil
}
