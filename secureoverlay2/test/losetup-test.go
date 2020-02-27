/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
        "fmt"
        //"github.com/freddierice/go-losetup"
        "rp.intel.com/intel/go-losetup"
)       

const (
	ImagePath = "/tmp/test.img"
)

func main() {
        
        dev, err := losetup.Attach(ImagePath, 0, false)
        if err != nil {
                fmt.Println(err.Error())
        }
        fmt.Println(dev)

        dev1, err := losetup.Attach(ImagePath, 0, false)
        if err != nil {
                fmt.Println(err.Error())
        }
        fmt.Println(dev1)
        
        info, err := dev1.GetInfo()
        fmt.Println(info.Flags)

        /*err = dev1.Detach()
        if err != nil {
                fmt.Println(err.Error())
        }*/
                
}       

