/*Copyright © 2018 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause

*/
// +build linux

package  kmsutility 

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"strconv"
	kms "github.com/docker/kmsconnector"
	"github.com/golang/glog"
)

//java path for unwrapping wrapped key
const (
	javaPath = "/opt/cit_k8s_extensions/bin/kmskeyunwrap.jar"
)

//Config for key encryption
type Config struct {
	AuthToken      string `json:"authtoken"`
	PrivateKeyPath string `json:"privkeypath"`
	TransferURL    string `json:"transferurl"`
}

//create config from lkp command
func createKey() (string, string, string, error) {
	cmd := []string{"/usr/bin/lkp", "create_key_for_encryption"}
	out, err := exec.Command(cmd[0], cmd[1]).Output()
	if err != nil {
		glog.Errorf("kmsutility:Error in getting configuration from lkp %s",err)
		return "", "", "", err
	}

	conf := Config{}

	err = json.Unmarshal(out, &conf)
	if err != nil {
		return "", "", "", err
	}

	return conf.AuthToken, conf.PrivateKeyPath, conf.TransferURL, nil

}

//getKmsAccessConf returns AuthToken and Private Key of non trusted node seperated by '#'
func getKmsAccessConf() (string, error) {
	cmd := []string{"/usr/bin/lkp", "get_kms_config"}
	kmsConfig, err := exec.Command(cmd[0], cmd[1]).Output()
	if err != nil {
		glog.Errorf("kmsutility:Error in getting kms configuration from lkp %s",err)
		return "", err
	}
	conf := Config{}

	er := json.Unmarshal(kmsConfig, &conf)
	if er != nil {
		return "", er
	}
	newstr := conf.AuthToken + "#" + conf.PrivateKeyPath
	return newstr, nil
}

//getHostAikKey check for host machine is trusted or untrusted 
func getHostAikKey(trustpath string) (string, error) {
	aikFilePath := trustpath + "/configuration/aik.pem"
	if _, err := os.Stat(aikFilePath); os.IsNotExist(err) {
		authPriKey, er := getKmsAccessConf()
		if er != nil {
			return "", er
		}
		return authPriKey, nil
	}
	return aikFilePath, nil
}

//unWrappKey returns actual key from wrapped key using private key on non trusted  machine
func unWrapKey(wrappedKeyPath string,privateKey string) (string, error) {
	if _, err := os.Stat(javaPath); os.IsNotExist(err) {
		return "", err
	}
	ky, err := exec.Command("java", "-jar", javaPath, privateKey, wrappedKeyPath).Output()
	if err != nil {
		glog.Errorf("kmsutility:Error in unwrap key on %v",err)
		return "", err
	}
	key := string(ky)
	key = strings.TrimSuffix(key, "\n")
	key = strings.TrimSpace(key)
	os.Remove(wrappedKeyPath)
	return key, nil

}

//unwrapaikkey unwraps the aik wrapped key using unbind aes key, binding key blob and passphrase on trusted host
func unWrapKeyWithTPM(wrappedAikKeyFilePath string,trustpath string) (string, error) {
	tpmUnbindaesKeyBinPath := trustpath + "/share/tpmtools/bin/tpm_unbindaeskey"
	tpmblobFilePath := trustpath + "/configuration/bindingkey.blob"

	cmd1 := "tagent export-config --stdout |  grep binding.key.secret   |  cut -d= -f2 "
	out, err := exec.Command("/bin/bash","-c", cmd1).CombinedOutput()
	if err != nil {
		glog.Errorf("kmsutility:Error in getting passphrase on trusted host  %v",err)
		return "", err
	}

	tpmPassphrase := string(out)
	tpmPassphrase = strings.TrimSuffix(tpmPassphrase, "\n")
	tpmPassphrase = strings.TrimSpace(tpmPassphrase)

	cmd := tpmUnbindaesKeyBinPath + " -k " + tpmblobFilePath + " -i " + wrappedAikKeyFilePath + " -q " + tpmPassphrase + " -x " + " | " + " base64"

	ky, er := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if er != nil {
		glog.Errorf("kmsutility:Error in getting unwrap key using tpm  %v",err)
		return "", er
	}
	key := string(ky)
	key = strings.TrimSuffix(key, "\n")
	key = strings.TrimSpace(key)

	os.Remove(wrappedAikKeyFilePath)
	return string(key), nil

}

//getKMSKeyon returns actual key used for encryption using Keytransfer Url
func GetKMSKeyForEncryption(keyHandle string,skipVerify bool) (string, string, error) {
	var auth = ""
	var priKey = ""
	if keyHandle == "" {
		var err error
		auth, priKey, keyHandle, err = createKey()
		if err != nil {
			return "", "", err
		}

	} else {
		authprikey, err := getKmsAccessConf()
		if err != nil {
			return "", "", err
		}

		kmsconfArray := strings.Split(authprikey, "#")
		if len(kmsconfArray) == 2 {
			auth = kmsconfArray[0]
			priKey = kmsconfArray[1]
		}
	}

	filepath ,err := kms.RetrieveWrappedKeyUsingAT(auth, keyHandle,skipVerify, nil)
	if err != nil {
		glog.Errorf("kmsutility:GetKMSKeyForEncryption: Error in getting wrapped key from kms  %v",err)
		return "", "", err
	}

	key, err1 := unWrapKey(filepath,priKey)
	if err1 != nil {
		return "", "", err1
	}

	return key, keyHandle, nil
}

//getKeyfromKMSforDecryption returns actual key used for encryption and Keytransfer Url which is disguised to be nil
func GetKeyfromKMSforDecryption(kmsHandle string,kmsProxyHost string,trustpath string) (string, string, error) {
	aikFile, err := getHostAikKey(trustpath)
	if err != nil {
		return "", "", err
	}

	  insecureSkipVerify := os.Getenv("INSECURE_SKIP_VERIFY")
        if len(insecureSkipVerify) == 0 {
                //if variable is not set in env default value false will be set
                insecureSkipVerify = "false"
        }
        skipVerify, _ := strconv.ParseBool(insecureSkipVerify)

	kmsconfArray := strings.Split(aikFile, "#")
	if len(kmsconfArray) == 2 {
		filepath,err := kms.RetrieveWrappedKeyUsingAT(kmsconfArray[0], kmsHandle,skipVerify, nil)
		if err != nil {
			glog.Errorf("kmsutility:GetKeyfromKMSforDecryption: Error in getting wrapped key from kms  %v",err)
			return "", "", err
		}

		key, err := unWrapKey(filepath,kmsconfArray[1])
		if err != nil {
			return "", "", err
		}
		return key, "", nil
	}
	filepath,err := kms.RetrieveWrappedKeyUsingAIK(aikFile, kmsHandle, kmsProxyHost,skipVerify, nil)
	if err != nil {
		glog.Errorf("kmsutility:GetKeyfromKMSforDecryption: Error in getting wrapped key from kms on trusted host %v",err)
		return "", "", err
	}

	key, er := unWrapKeyWithTPM(filepath,trustpath)
	if er != nil {
		return "", "", er
	}

	return key, "", nil
}
