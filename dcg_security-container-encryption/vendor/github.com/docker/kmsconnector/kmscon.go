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
	"os/exec"
	"strings"
)

//GetConfPath to get confpath for temporary files
func GetConfPath() string {
	confPath := "/opt/cit_k8s_extensions/work"
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		os.MkdirAll(confPath, 0740)
	}
	return confPath 
}

//RetrieveWrappedKeyUsingAT KMS...
func RetrieveWrappedKeyUsingAT(authToken string, kmsURL string, skipVerify bool,requestBody []byte) error {
	var buffer bytes.Buffer
	confPath := GetConfPath()
	wrappedKeyPath := confPath + "/wrapped_key"
	request, err := http.NewRequest("POST", kmsURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
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
		return err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return err1
	}
	if response.StatusCode != 200 {
		return errors.New(response.Status)
	}
	buf := map[string]interface{}{}
	er := json.Unmarshal(data, &buf)
	if er != nil {
		return er
	}

	er = ioutil.WriteFile(wrappedKeyPath, []byte(buf["key"].(string)), 0744)
	if er != nil {
		return er
	}
	return nil
}

//RetrieveWrappedKeyUsingAIK ...
func RetrieveWrappedKeyUsingAIK(aikFile string, transferURL string, proxyHost string,skipVerify bool, requestBody []byte) error {
	confPath := GetConfPath()
	aikKeyPath := confPath + "/aikKey"
	entrustCert, _ := ioutil.ReadFile(aikFile)
	body := strings.NewReader(string(entrustCert))

	request, err := http.NewRequest("POST", transferURL, body)
	if err != nil {
		return err
	}

	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Content-Type", "application/x-pem-file")

	proxyURL, er := url.Parse(proxyHost)
	if er != nil {
		return er
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err1 := ioutil.ReadAll(response.Body)
	if err1 != nil {
		return err1
	}
	if response.StatusCode != 200 {
		return errors.New(response.Status)
	}
	err = ioutil.WriteFile(aikKeyPath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

//Get digest for docker image from docker registry
func GetDigest(image string, tag string, dockerRegistry string, skipVerify bool) (string, error) {
	confPath := GetConfPath()
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

	filepath := confPath + "/digest.json"
	err = ioutil.WriteFile(filepath, data, 0744)
	if err != nil {
		return "", err
	}

	cmd := "cat " + filepath + " | " + "jq -r '.config.digest'"
	configdigest, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return "", err
	}
	digest := string(configdigest)
	digest = strings.TrimSuffix(digest, "\n")
	digest = strings.TrimSpace(digest)

	_, err = exec.Command("/bin/rm", "-rf", filepath).Output()
	if err != nil {
		log.Println("Error: %v", err)
	}
	return digest, nil

}

//Get TransferURL using docker inspect
func GetTransferUrlFromInspect(image string, digest string, dockerRegistry string, skipVerify bool) (string, error) {
	confPath := GetConfPath()
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

	filepath := confPath + "/metadata.json"
	err = ioutil.WriteFile(filepath, data, 0744)
	if err != nil {
		return "", err
	}
	cmd1 := "cat " + filepath + " | " + "jq -r '.history[-1]'"
	cmd2 := `  awk -F"," '/securityopts/ {
    for( i=1; i < NF; i++) {
       if( match( $i, /KeyHandle/) ){
           split( $i, a," " )
           print a[length(a)]
       }
    }
  }' | cut -d\" -f4 | cut -d\\ -f1`
	cmd := cmd1 + "|" + cmd2
	trasferURL, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return "", err
	}
	keyHandle := string(trasferURL)
	keyHandle = strings.TrimSuffix(keyHandle, "\n")
	keyHandle = strings.TrimSpace(keyHandle)

	_, err = exec.Command("/bin/rm", "-rf", filepath).Output()
	if err != nil {
		log.Println("Error: %v", err)
	}

	return keyHandle, nil

}
