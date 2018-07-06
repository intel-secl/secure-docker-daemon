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
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"math/rand"
	"time"
 "github.com/buger/jsonparser"
)

//To generate random number
const charset = "abcdefghijklmnopqrstuvwxyz" +
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
  rand.NewSource(time.Now().UnixNano()))

//GetConfPath to get confpath for temporary files
func GetConfPath() string {
	confPath := "/opt/cit_k8s_extensions/work"
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		os.MkdirAll(confPath, 0740)
	}
	return confPath 
}


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



//RetrieveWrappedKeyUsingAT KMS...
func RetrieveWrappedKeyUsingAT(authToken string, kmsURL string, skipVerify bool,requestBody []byte) (string,error) {
	var buffer bytes.Buffer
	confPath := GetConfPath()
	filenumber := StringWithCharset(16,charset) 
	wrappedKeyPath := confPath + "/" + filenumber +  "_wrapped_key"
	request, err := http.NewRequest("POST", kmsURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "",err
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
		return "",err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "",err1
	}
	if response.StatusCode != 200 {
		return "",errors.New(response.Status)
	}
	buf := map[string]interface{}{}
	er := json.Unmarshal(data, &buf)
	if er != nil {
		return "",er
	}

	er = ioutil.WriteFile(wrappedKeyPath, []byte(buf["key"].(string)), 0744)
	if er != nil {
		return "",er
	}
	return wrappedKeyPath, nil
}

//RetrieveWrappedKeyUsingAIK ...
func RetrieveWrappedKeyUsingAIK(aikFile string, transferURL string, proxyHost string,skipVerify bool, requestBody []byte) (string,error) {
	rand.Seed(time.Now().UTC().UnixNano())
	filenumber := StringWithCharset(16,charset) 
	confPath := GetConfPath()
	aikKeyPath := confPath + "/" + filenumber + "_aikKey"
	entrustCert, _ := ioutil.ReadFile(aikFile)
	body := strings.NewReader(string(entrustCert))

	request, err := http.NewRequest("POST", transferURL, body)
	if err != nil {
		return "",err
	}

	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Content-Type", "application/x-pem-file")

	proxyURL, er := url.Parse(proxyHost)
	if er != nil {
		return "",er
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "",err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "",err1
	}
	if response.StatusCode != 200 {
		return "",errors.New(response.Status)
	}
	err = ioutil.WriteFile(aikKeyPath, data, 0644)
	if err != nil {
		return "",err
	}

	return aikKeyPath,nil
}

//Get digest for docker image from docker registry
func GetDigest(image string, tag string, dockerRegistry string, skipVerify bool) (string, error) {
	//confPath := GetConfPath()
	url := dockerRegistry + "/v2/" + image + "/manifests/" + tag

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	request.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "", err1
	}
	if response.StatusCode != 200 {
		return "", errors.New(response.Status)
	}

 	digest,_,_,err := jsonparser.Get(data,"config","digest")
        log.Println("digest output is",digest)

	return string(digest), nil

}

//Get TransferURL using docker inspect
func GetTransferUrlFromInspect(image string, digest string, dockerRegistry string, skipVerify bool) (string, error) {
	//confPath := GetConfPath()
	var keyHandle string
	url := dockerRegistry + "/v2/" + image + "/blobs/" + digest

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	request.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return "", err1
	}
	if response.StatusCode != 200 {
		return "", errors.New(response.Status)
	}

	 hist,_,_,err := jsonparser.Get(data,"history")
	 jsonparser.ArrayEach(hist, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
        secopts,_,_,_ := jsonparser.Get(value, "securityopts")
	  sec :=  strings.Split(string(secopts),"\\")
        for key,val := range sec{
                if key == 7 {
                        transferURL := strings.Split(val,"\"")
			keyHandle = strings.Join(transferURL,"")
        }
        }
})

	return keyHandle, nil

}
