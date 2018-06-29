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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

//GetConfPath to get confpath for temporary files
func GetConfPath() (string, bool) {
	confPath := "/opt/cit_k8s_extensions/work"
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		os.MkdirAll(confPath, 0740)
	}
	skipVerify := os.Getenv("Insecure_Skip_Verify")
	if len(skipVerify) == 0 {
		return confPath, false
	}
	sv, _ := strconv.ParseBool(skipVerify)
	return confPath, sv
}

//RetrieveWrappedKeyUsingAT KMS...
func RetrieveWrappedKeyUsingAT(authToken string, kmsURL string, requestBody []byte) error {
	var buffer bytes.Buffer
	confPath, skipVerify := GetConfPath()
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
func RetrieveWrappedKeyUsingAIK(aikFile string, transferURL string, proxyHost string, requestBody []byte) error {
	confPath, skipVerify := GetConfPath()
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
