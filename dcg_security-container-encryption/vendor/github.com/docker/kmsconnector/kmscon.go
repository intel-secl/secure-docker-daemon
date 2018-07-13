/*Copyright © 2018 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package kmsconnector

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//To generate random number ,the number will be used to create filenames for wrapped key
const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}

//GetWorkDirPath to get workDirpath for temporary files
func GetTempDirPath() string {
	tempDirPath := "/tmp/cit_k8s_extensions/"
	if _, err := os.Stat(tempDirPath); os.IsNotExist(err) {
		os.MkdirAll(tempDirPath, 0740)
	}
	return tempDirPath
}

//RetrieveWrappedKeyUsingAT KMS... Wrapped key from kms will be fetched using authorization token 
//the json response will be unmarshalled and wrapped key will be redirected to file, filepath will be returned to calling function
func RetrieveWrappedKeyUsingAT(authToken string, kmsURL string, skipVerify bool, requestBody []byte) (string, error) {
	var buffer bytes.Buffer
	tempDirPath := GetTempDirPath()

	goto createFilePath

//create random filename for wrapped key
createFilePath:
	filenumber := StringWithCharset(16, charset)
	wrappedKeyPath := tempDirPath + filenumber + "_wrapped_key"
	if _, err := os.Stat(wrappedKeyPath); err == nil {
		goto createFilePath
	}

	//POST call to kms to fetch wrapped key
	request, err := http.NewRequest("POST", kmsURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	buffer.WriteString("Token ")
	buffer.WriteString(authToken)

	request.Header.Set("Authorization", buffer.String())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", errors.New(response.Status)
	}

	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "", err1
	}
	buf := map[string]interface{}{}
	//the json response body from POST call will be unmarshaled and data will be populated in map
	er := json.Unmarshal(data, &buf)
	if er != nil {
		return "", er
	}

	//wrapped key will written to file
	er = ioutil.WriteFile(wrappedKeyPath, []byte(buf["key"].(string)), 0744)
	if er != nil {
		return "", er
	}
	//wrapped key filepath will be return
	return wrappedKeyPath, nil
}

//RetrieveWrappedKeyUsingAIK ...wrapped key will be fetched using aik key 
//the response will be in octet-stream  redirected to file, filepath will be returned to calling function
func RetrieveWrappedKeyUsingAIK(aikFile string, transferURL string, proxyHost string, skipVerify bool, requestBody []byte) (string, error) {
	tempDirPath := GetTempDirPath()

	goto CreateFilePath

//create random filename for wrapped key
CreateFilePath:
	filenumber := StringWithCharset(16, charset)
	aikKeyPath := tempDirPath + filenumber + "_aikKey"
	if _, err := os.Stat(aikKeyPath); err == nil {
		goto CreateFilePath
	}
	entrustCert, _ := ioutil.ReadFile(aikFile)
	body := strings.NewReader(string(entrustCert))

	//POST call to kms to fetch wrapped key
	request, err := http.NewRequest("POST", transferURL, body)
	if err != nil {
		return "", err
	}

	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Content-Type", "application/x-pem-file")

	proxyURL, er := url.Parse(proxyHost)
	if er != nil {
		return "", er
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", errors.New(response.Status)
	}

	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "", err1
	}
	err = ioutil.WriteFile(aikKeyPath, data, 0644)
	if err != nil {
		return "", err
	}

	return aikKeyPath, nil
}
