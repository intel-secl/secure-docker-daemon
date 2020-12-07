/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package secureoverlay

import (
	"bytes"
	"context"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/internal/test/fakecontext"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/skip"

	"github.com/docker/docker/integration/internal/container"

)

type TestData struct {
	name                           string
	imgtag                         string
	dockerfile                     string
	copts                          []string
}

const secureMetadataKey string = "security-meta-data"

var ctx = context.Background()

func imageSave(client client.APIClient, path, image string) error {
	responseReader, err := client.ImageSave(ctx, []string{image})
	if err != nil {
		return err
	}
	defer responseReader.Close()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, responseReader)
	return err
}

func imageLoad(client client.APIClient, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	quiet := true
	response, err := client.ImageLoad(ctx, file, quiet)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func imageImport(client client.APIClient, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	options := types.ImageImportOptions{}
	ref := ""
	source := types.ImageImportSource{
		Source:     file,
		SourceName: "-",
	}
	responseReader, err := client.ImageImport(ctx, source, ref, options)
	if err != nil {
		return err
	}
	defer responseReader.Close()
	return nil
}

func RunSecureOverlaySuccessBuildTest(t *testing.T, c TestData){
	client := testEnv.APIClient()

	t.Run(c.name, func(t *testing.T) {
		source := fakecontext.New(t, "", fakecontext.WithDockerfile(c.dockerfile))
		defer source.Close()


		mytags := []string{c.imgtag}

		resp, err := client.ImageBuild(ctx, source.AsTarReader(t), types.ImageBuildOptions{Tags: mytags, ImgCryptOpt: c.copts})
		assert.NilError(t, err)
		defer resp.Body.Close()

		// check if the image was built
		out := bytes.NewBuffer(nil)
		assert.NilError(t, err)
		_, err = io.Copy(out, resp.Body)
		resp.Body.Close()
		assert.NilError(t, err)

		assert.Check(t, is.Contains(out.String(), "Successfully built"), "Image not built: build output: \n " + out.String())

		// check if the security-meta-data was added to the image
		imageInspectResponse, _, err := client.ImageInspectWithRaw(ctx, c.imgtag)
		if err != nil {
			t.Fatal(err)
		}

		assert.Check(t, is.Contains(imageInspectResponse.GraphDriver.Data, secureMetadataKey), "security-meta-data not /" +
			" present in encrypted image actual: %v", imageInspectResponse.GraphDriver.Data)
	})
}

func TestSecureOverlayEncryptedImageFromVanillaBase(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()

	c := TestData{
		name: "Encrypted image built from vanilla base image",
		imgtag: "myimg1",
		dockerfile: `FROM busybox
                        ENV somethingintheenv mybad
                        RUN touch something && echo "This is my first commit to a container" > something`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)
}

func TestSecureOverlayEncryptedImageFromEncryptedBase(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()

	c := TestData{
		name: "Encrypted image built from vanilla base image",
		imgtag: "myimg2",
		dockerfile: `FROM busybox
                        ENV somethingintheenv mybad
                        RUN touch something && echo "This is my first commit to a container" > something`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)

	c = TestData{
		name: "Encrypted image built from encrypted base image",
		imgtag: "myimg3",
		dockerfile: `FROM myimg2
                        RUN touch something4 something5 && echo "This is my second commit to a container" > something5`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)
}

func TestSecureOverlayEncryptedImageFromLargeBaseImage(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: secureoverlay2 is supported only on linux")
	defer setupTest(t)()

	c := TestData{
		name: "Encrypted image built with large base image from DockerHub",
		imgtag: "myimg4",
		dockerfile: `FROM postgres
                        RUN touch something7 && echo "This is my seventh commit to a container" > something7`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)
}

func TestSecureOverlayVanillaImageFromEncryptedBase(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()

	c := TestData{
		name: "Encrypted image built from vanilla base image",
		imgtag: "myimg5",
		dockerfile: `FROM busybox
                        ENV somethingintheenv mybad
                        RUN touch something && echo "This is my first commit to a container" > something`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)

	c = TestData{
		name: "Vanilla image built with encrypted base image from DockerHub",
		imgtag: "myimg6",
		dockerfile: `FROM myimg5
                        RUN touch something10 && echo "This is my tenth commit to a container" > something10`,
		copts: []string{},
	}

	client := testEnv.APIClient()

	t.Run(c.name, func(t *testing.T) {
		source := fakecontext.New(t, "", fakecontext.WithDockerfile(c.dockerfile))
		defer source.Close()

		mytags := []string{c.imgtag}

		resp, err := client.ImageBuild(ctx, source.AsTarReader(t), types.ImageBuildOptions{Tags: mytags})
		assert.NilError(t, err)
		defer resp.Body.Close()

		// check if the image was built
		out := bytes.NewBuffer(nil)
		assert.NilError(t, err)
		_, err = io.Copy(out, resp.Body)
		resp.Body.Close()
		assert.NilError(t, err)

		assert.Check(t, is.Contains(out.String(), "Successfully built"), "Image not built: build output: \n " + out.String())

		// the security-meta-data should not be added - same as a vanilla image
		imageInspectResponse, _, err := client.ImageInspectWithRaw(ctx, mytags[0])
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		_, ok = imageInspectResponse.GraphDriver.Data[secureMetadataKey]
		assert.Check(t, !ok, "security-meta-data not present in an unencrypted image : %v", imageInspectResponse.GraphDriver.Data)
	})
}

func TestSecureOverlayNoopBuild(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()

	c  := TestData{
		name: "successful encrypted image build with only noop changes",
		imgtag: "myimg7",
		dockerfile: `FROM busybox
					ENV somethingintheenv mybad
					ENV somethingelse mygood`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	client := testEnv.APIClient()
	ctx := context.Background()

	t.Run(c.name, func(t *testing.T) {
		source := fakecontext.New(t, "", fakecontext.WithDockerfile(c.dockerfile))
		defer source.Close()

		mytags := []string{c.imgtag}

		resp, err := client.ImageBuild(ctx, source.AsTarReader(t), types.ImageBuildOptions{Tags: mytags, ImgCryptOpt: c.copts})
		assert.NilError(t, err)
		defer resp.Body.Close()

		// check if the image was built
		out := bytes.NewBuffer(nil)
		assert.NilError(t, err)
		_, err = io.Copy(out, resp.Body)
		resp.Body.Close()
		assert.NilError(t, err)

		assert.Check(t, is.Contains(out.String(), "Successfully built"), "Image not built: build output: \n " + out.String())

		// the security-meta-data should not be added - same as a vanilla image
		imageInspectResponse, _, err := client.ImageInspectWithRaw(ctx, mytags[0])
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		_, ok = imageInspectResponse.GraphDriver.Data[secureMetadataKey]
		assert.Check(t, !ok, "security-meta-data should not present where no changes or only noop changes are made to base image : %v", imageInspectResponse.GraphDriver.Data)
	})
}

func TestSecureOverlayImageLoadSave(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()

	c := TestData{
		name: "Encrypted image built from vanilla base image",
		imgtag: "busyboxenc",
		dockerfile: `FROM busybox
                        ENV somethingintheenv mybad
                        RUN touch something && echo "This is my first commit to a container" > something
						ENTRYPOINT ["/bin/sh", "-c", "echo Something $SOMETHINGINTHEENV"]`,
		copts: []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"},
	}

	RunSecureOverlaySuccessBuildTest(t, c)

	client := testEnv.APIClient()
	ctx := context.Background()

	tmp, err := ioutil.TempDir("", "secureoverlay-img-loadsave")
	assert.NilError(t, err)
	defer os.RemoveAll(tmp)

	savedImagePath := filepath.Join(tmp, "save.tar")

	err = imageSave(client, savedImagePath, "busyboxenc")
	assert.NilError(t, err)
	err = imageLoad(client, savedImagePath)
	assert.NilError(t, err)

	exportedImagePath := filepath.Join(tmp, "export.tar")

	cID := container.Run(t, ctx, client)

	responseReader, err := client.ContainerExport(context.Background(), cID)
	assert.NilError(t, err)
	defer responseReader.Close()
	file, err := os.OpenFile(exportedImagePath, os.O_CREATE|os.O_RDWR, 0600)
	assert.NilError(t, err)
	defer file.Close()
	_, err = io.Copy(file, responseReader)
	assert.NilError(t, err)

	err = imageImport(client, exportedImagePath)
	assert.NilError(t, err)
}

func TestSecureOverlayRunEncryptedImage(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Secureoverlay2 on Windows is not supported in this release!")
	defer setupTest(t)()
	client := testEnv.APIClient()
	CRYPTOPTS := []string {"KeyType=key-type-string",  "KeyTypeOption=MyP@ssw0rd", "RequiresConfidentiality=true"}


	testCases := []struct {
		name          string
		image         string
		dockerfile    string
		outputmsg     string
	}{
		{
			name:          "Containers can be spun up from encrypted images",
			image:         "myimg:enc",
			dockerfile: `FROM ubuntu:latest
			ENV SOMETHINGINTHEENV "smells funny"
			RUN touch something something2 something3 && echo "This is my first commit to a container" > something
			ENTRYPOINT ["/bin/sh", "-c", "echo Something $SOMETHINGINTHEENV"]`,
			outputmsg:	"Something smells funny",
		},
		{
			name:          "Containers can be spun up from multi-layered encrypted images",
			image:         "myimg:encmulti",
			dockerfile: `FROM myimg:enc
			ENV SOMETHINGINTHEENV "looks good"
			RUN touch something4 && echo "This is my first commit to a container" > something4
			ENTRYPOINT ["/bin/sh", "-c", "echo Something in the env $SOMETHINGINTHEENV"]`,
			outputmsg:	"Something in the env looks good",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			source := fakecontext.New(t, "", fakecontext.WithDockerfile(tc.dockerfile))
			defer source.Close()
			resp, err := client.ImageBuild(ctx, source.AsTarReader(t), types.ImageBuildOptions{Tags: []string{tc.image}, ImgCryptOpt: CRYPTOPTS})

			assert.NilError(t, err)
			defer resp.Body.Close()

			// check if the image was built
			out := bytes.NewBuffer(nil)
			assert.NilError(t, err)
			_, err = io.Copy(out, resp.Body)
			resp.Body.Close()
			assert.NilError(t, err)

			assert.Check(t, is.Contains(out.String(), "Successfully built"), "Image not built: build output: \n "+out.String())

			cID := container.Run(t, ctx, client, container.WithImage(tc.image))
			reader, err := client.ContainerLogs(ctx, cID, types.ContainerLogsOptions{
				ShowStdout: true,
			})
			assert.NilError(t, err)

			actualStdout := new(bytes.Buffer)
			actualStderr := ioutil.Discard
			_, err = stdcopy.StdCopy(actualStdout, actualStderr, reader)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(strings.TrimSpace(actualStdout.String()), tc.outputmsg), "Run output does not match | Expected: %s | Actual: %s ", actualStdout.String(), tc.outputmsg)
		})
	}
}
