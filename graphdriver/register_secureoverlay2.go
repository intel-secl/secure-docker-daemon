// +build !exclude_graphdriver_overlay2,linux

package register // import "github.com/docker/docker/daemon/graphdriver/register"

import (
        // register the secureoverlay2 graphdriver
        _ "github.com/docker/docker/daemon/graphdriver/secureoverlay2"
)

