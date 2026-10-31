//go:build linux

package tun

import "github.com/sagernet/netlink"

func (r *autoRedirect) routeRulePriority() int {
	if r.ownership != nil {
		return r.ownership.RulePriority
	}
	return redirectRouteRulePriority
}

func (r *autoRedirect) flushOwnedRouteTable(table int) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return
	}
	for _, route := range routes {
		if int(route.Protocol) == r.tunOptions.OwnedRouteProtocol {
			_ = netlink.RouteDel(&route)
		}
	}
}
