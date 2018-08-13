package kmsutility

import (
	"os"
	"strconv"
)

type EnvVariables struct {
	Username       string
	Password       string
	SchemeType     string
	Trustagentpath string
	Kmsproxyhost   string
	Keyexpiretime  string
	SkipVerify     bool
}

//getEnv will read environment variables from prefetchplugin.conf if set else set default values for variables...
func (ev *EnvVariables) GetEnv() {
	insecureSkipVerify := ""

	ev.Username = os.Getenv("REGISTRY_USERNAME")
	ev.Password = os.Getenv("REGISTRY_PASSWORD")

	ev.SchemeType = os.Getenv("REGISTRY_SCHEME_TYPE")
	if ev.SchemeType == "" {
		ev.SchemeType = "https"
	}

	insecureSkipVerify = os.Getenv("INSECURE_SKIP_VERIFY")
	if len(insecureSkipVerify) == 0 {
		//if variable is not set in env default value false will be set
		insecureSkipVerify = "false"
	}
	ev.SkipVerify, _ = strconv.ParseBool(insecureSkipVerify)

	ev.Trustagentpath = os.Getenv("TRUST_AGENT_PATH")
	if ev.Trustagentpath == "" {
		//if path is not set in env default path will be set
		ev.Trustagentpath = "/opt/trustagent"
	}

	//kms_proxy_host is address for kmsproxy server
	ev.Kmsproxyhost = os.Getenv("KMS_PROXY_HOST")
	ev.Keyexpiretime = os.Getenv("KEY_EXPIRE_TIME_INSEC")

}
