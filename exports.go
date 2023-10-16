package figure

import (
	_ "github.com/szkiba/xk6-g0"
	"github.com/szkiba/xk6-g0/g0"
	"github.com/traefik/yaegi/interp"
	"go.k6.io/k6/js/modules"
)

var Symbols = interp.Exports{}

func exports(vu modules.VU) interp.Exports {
	return Symbols
}

func init() {
	g0.RegisterExports(exports)
}
