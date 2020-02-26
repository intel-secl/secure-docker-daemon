// +build !exclude_graphdriver_overlay2,linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package register // import "github.com/docker/docker/daemon/graphdriver/register"

import (
        // register the secureoverlay2 graphdriver
        _ "github.com/docker/docker/daemon/graphdriver/secureoverlay2"
)

