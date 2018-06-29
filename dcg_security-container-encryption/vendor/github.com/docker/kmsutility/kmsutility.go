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
	"log"
	kms "github.com/docker/kmsconnector"
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
		log.Println("lkp create_key_for_encryption error : ", err)
		return "", "", "", err
	}

	conf := Config{}

	err = json.Unmarshal(out, &conf)
	if err != nil {
		log.Println("lkp create_key_for_encryption Unmarshal error : ", err)
		return "", "", "", err
	}

	return conf.AuthToken, conf.PrivateKeyPath, conf.TransferURL, nil

}

//getKmsAccessConf returns AuthToken and Private Key of developer seperated by '#'
func getKmsAccessConf() (string, error) {
	cmd := []string{"/usr/bin/lkp", "get_kms_config"}
	cmdResponse, err := exec.Command(cmd[0], cmd[1]).Output()
	if err != nil {
		log.Println("Its not a developer machine and lkp is not present on this host err: %s ", err)
		return "", err
	}
	conf := Config{}

	newerr := json.Unmarshal(cmdResponse, &conf)
	if newerr != nil {
		log.Println("Error to unmarshell config out from lkp :%s ", newerr)
		return "", newerr
	}
	newstr := conf.AuthToken + "#" + conf.PrivateKeyPath
	return newstr, nil
}

//getHostAikKey
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

//checkDevNode returns true if it is a dev node (identified by issuing the lkp command), false otherwise
func isDevNode() bool {
	cmd := []string{"/usr/bin/lkp", "get_kms_config"}
	cmdResponse, err := exec.Command("/bin/bash", "-c", cmd[0], cmd[1]).Output()
	if err != nil {
		log.Println("Its not a developer machine and AIK also does not exists for this host err: %s ", err)
		return false
	}
	log.Println("Its developer machine %s ", cmdResponse)
	return true
}

//unWrappKey returns actual key from wrapped key using private key on developer machine
func unWrapKeyOnDev(privateKey string) (string, error) {
	confPath := kms.GetConfPath()
	wrappedKeyPath := confPath + "/wrapped_key"
	if _, e := os.Stat(javaPath); os.IsNotExist(e) {
		return "", e
	}
	key1, err := exec.Command("java", "-jar", javaPath, privateKey, wrappedKeyPath).Output()
	if err != nil {
		return "", err
	}
	k := string(key1)
	k = strings.TrimSuffix(k, "\n")
	k = strings.TrimSpace(k)
	_, err = exec.Command("/bin/rm", "-rf", wrappedKeyPath).Output()
	if err != nil {
		log.Println("file is not exist ", wrappedKeyPath, err)
	}
	return k, nil

}

//unwrapaikkey unwraps the aik wrapped key using unbind aes key, binding key blob and passphrase on trusted host
func unWrapKeyOnHost(trustpath string) (string, error) {

	confPath := kms.GetConfPath()
	taikpem := confPath + "/aikKey"

	tpma := trustpath + "/share/tpmtools/bin/tpm_unbindaeskey"
	tpmblob := trustpath + "/configuration/bindingkey.blob"

	cmd1 := "tagent export-config --stdout |  grep binding.key.secret   |  cut -d= -f2 "
	out, err := exec.Command("/bin/bash", "-c", cmd1).CombinedOutput()
	if err != nil {
		return "", err
	}

	passphrase := string(out)
	passphrase = strings.TrimSuffix(passphrase, "\n")
	passphrase = strings.TrimSpace(passphrase)

	cmd := tpma + " -k " + tpmblob + " -i " + taikpem + " -q " + passphrase + " -x " + " | " + " base64"

	ky, er := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if er != nil {
		return "", er
	}
	k := string(ky)
	k = strings.TrimSuffix(k, "\n")
	k = strings.TrimSpace(k)

	_, err = exec.Command("/bin/rm", "-rf", taikpem).Output()
	if err != nil {
		log.Println("file is not exist ", taikpem, err)
	}
	return string(k), nil

}

//getKMSKeyonDev returns actual key used for encryption using Keytransfer Url
func GetKMSKeyonDev(keyHandle string,skipVerify bool) (string, string, error) {
	var auth = ""
	var priKey = ""
	if keyHandle == "" {
		var err error
		auth, priKey, keyHandle, err = createKey()

		if err != nil {
			log.Println("getKMSKeyonDev: from createKey ", err)
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

	err := kms.RetrieveWrappedKeyUsingAT(auth, keyHandle,skipVerify, nil)
	if err != nil {
		log.Println("getKMSKeyonDev:error from RetrieveWrappedKeyUsingAT ", err)
		return "", "", err
	}

	ky, err1 := unWrapKeyOnDev(priKey)
	if err1 != nil {
		log.Println("getKMSKeyonDev:error from unWrapKey", err1)
		return "", "", err1
	}

	return ky, keyHandle, nil
}

//getKeyfromKMSforDecryption returns actual key used for encryption and Keytransfer Url which is disguised to be nil
func GetKeyfromKMSforDecryption(kmsHandle string,kmsProxyHost string,trustpath string,skipVerify bool) (string, string, error) {
	aikFile, err := getHostAikKey(trustpath)
	if err != nil {
		log.Println("getKeyfromKMSforDecryption: Error getting Key err: %s", err)
		return "", "", err
	}

	kmsconfArray := strings.Split(aikFile, "#")
	if len(kmsconfArray) == 2 {
		err := kms.RetrieveWrappedKeyUsingAT(kmsconfArray[0], kmsHandle,skipVerify, nil)
		if err != nil {
			log.Println("getKeyfromKMSforDecryption: error from RetrieveWrappedKeyUsingAT ", err)
			return "", "", err
		}

		ky, err1 := unWrapKeyOnDev(kmsconfArray[1])
		if err1 != nil {
			log.Println("getKeyfromKMSforDecryption: error from unWrapKey", err1)
			return "", "", err1
		}
		return ky, "", nil
	}
	err = kms.RetrieveWrappedKeyUsingAIK(aikFile, kmsHandle, kmsProxyHost,skipVerify, nil)
	if err != nil {
		log.Println("getKeyfromKMSforDecryption: error from RetrieveWrappedKeyUsingAIK", err)
		return "", "", err
	}

	ky, er := unWrapKeyOnHost(trustpath)
	if er != nil {
		log.Println("getKeyfromKMSforDecryption: error from unWrapKeyOnHost", er)
		return "", "", er
	}

	return ky, "", nil
}
